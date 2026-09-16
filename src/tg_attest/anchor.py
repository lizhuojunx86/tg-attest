"""
tg-attest.anchor — RFC 3161 外部时间戳锚定。

为什么必须有这一层：
    自己控制的哈希链对自己不构成证据。你有写权限，就能整条重写并重算全部
    哈希，链依然自洽。record.py 里的场景 B 演示的正是这一点——防住"事后
    改一条"，防不住"事后重建全部"。
    只有把 epoch 根交给一个不受你控制的第三方签名，"这批记录在时刻 T
    之前就已存在"才成为可对抗你自己的断言。

    eIDAS 下合格时间戳具备法律推定效力，成本以分计。这是"有日志"和
    "有证据"之间的分界线，半天工作量。

架构上刻意切成两半，依赖画像不同：
    写入路径 (anchor)  —— 零依赖，只用 stdlib。跑在生产热路径上，
                          不能因为一个 crypto 库的版本冲突拖垮部署。
    验证路径 (verify) —— 需要真正的 CMS/X.509 校验，放在审计侧或离线
                          任务里，允许有依赖。

最重要的一条设计原则：
    产出物必须是标准 .tsq / .tsr 文件，审计方用 `openssl ts -verify`
    就能独立验证，**不需要安装 tg-attest**。证据的可信度不能依赖于
    对方信任你的库。
"""

from __future__ import annotations

import base64
import logging
import secrets
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 最小 DER 编码器
# ---------------------------------------------------------------------------
# TimeStampReq 是个很小的结构，手写编码可以做到零依赖，且能与 openssl 的
# 输出逐字节比对来验证正确性（见 selftest）。
# 但*验证*不能手写——那需要完整 CMS + X.509 链校验，手搓等于自造漏洞。

SHA256_OID = (2, 16, 840, 1, 101, 3, 4, 2, 1)


def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _len(len(value)) + value


def der_int(n: int) -> bytes:
    if n == 0:
        return _tlv(0x02, b"\x00")
    b = n.to_bytes((n.bit_length() + 8) // 8, "big")  # +8 保证正数不被读成负数
    return _tlv(0x02, b.lstrip(b"\x00") if b[0] == 0 and b[1] < 0x80 else b)


def der_oid(arcs: tuple[int, ...]) -> bytes:
    out = bytes([40 * arcs[0] + arcs[1]])
    for a in arcs[2:]:
        chunk = bytearray([a & 0x7F])
        a >>= 7
        while a:
            chunk.insert(0, (a & 0x7F) | 0x80)
            a >>= 7
        out += bytes(chunk)
    return _tlv(0x06, out)


def der_octets(b: bytes) -> bytes:
    return _tlv(0x04, b)


def der_seq(*parts: bytes) -> bytes:
    return _tlv(0x30, b"".join(parts))


DER_NULL = b"\x05\x00"
DER_TRUE = b"\x01\x01\xff"


def build_tsq(digest: bytes, *, nonce: int | None = None,
              cert_req: bool = True) -> bytes:
    """构造 RFC 3161 TimeStampReq（.tsq）。

    cert_req=True 让 TSA 把签名证书一并放进 token —— 体积大几 KB，但
    换来 token 自包含，审计方不需要再去找 TSA 的证书。合规场景永远选自包含。
    """
    if len(digest) != 32:
        raise ValueError("本实现固定 SHA-256，digest 必须 32 字节")
    imprint = der_seq(der_seq(der_oid(SHA256_OID) + DER_NULL), der_octets(digest))
    parts = [der_int(1), imprint]
    if nonce is not None:
        parts.append(der_int(nonce))
    if cert_req:
        parts.append(DER_TRUE)
    return der_seq(*parts)


# ---------------------------------------------------------------------------
# 最小 DER 遍历器（只用于剥离响应外壳，不做任何密码学判断）
# ---------------------------------------------------------------------------

def _read_tlv(buf: bytes, i: int) -> tuple[int, bytes, int]:
    """读一个 TLV。越界一律抛异常，不返回截断的结果。

    原来的写法用 buf[i:i+n] 取值，长度字段声称 500 字节而实际只剩 9 字节时，
    切片会安静地返回那 9 字节，解析继续往下走。对一个只负责剥壳的函数来说，
    「安静地少给你一些字节」是最坏的失败方式——它把一个格式错误变成了
    一份看起来能用的数据。
    """
    if i + 2 > len(buf):
        raise ValueError("DER 截断：读不到 tag/length")
    tag = buf[i]
    i += 1
    n = buf[i]
    i += 1
    if n & 0x80:
        k = n & 0x7F
        if k == 0:
            raise ValueError("DER 不定长编码不被支持")
        if i + k > len(buf):
            raise ValueError("DER 截断：长度字段本身越界")
        n = int.from_bytes(buf[i:i + k], "big")
        i += k
    if i + n > len(buf):
        raise ValueError(f"DER 截断：声称 {n} 字节，实际只剩 {len(buf) - i}")
    return tag, buf[i:i + n], i + n


PKI_STATUS = {0: "granted", 1: "grantedWithMods", 2: "rejection",
              3: "waiting", 4: "revocationWarning", 5: "revocationNotification"}


def parse_tsr(tsr: bytes) -> tuple[str, bytes | None]:
    """从 TimeStampResp 中取出状态与 TimeStampToken（DER）。

    只解析结构、不验签。验签是 verify_token() 的事，且需要额外依赖。
    未知状态码返回 "unknown(N)"，而 Anchor.ok 只认 granted/grantedWithMods，
    所以认不出来的状态一律不算成功。
    """
    _, body, _ = _read_tlv(tsr, 0)                 # TimeStampResp SEQUENCE
    _, status_info, after = _read_tlv(body, 0)     # PKIStatusInfo
    _, status_bytes, _ = _read_tlv(status_info, 0)
    status = int.from_bytes(status_bytes, "big")

    token = body[after:] if after < len(body) else None
    if token is not None:
        # 剩下的字节必须自己就是一个完整的 TLV。不检查的话，任何尾随垃圾
        # 都会被当成 token 存下来，直到几个月后审计时才发现它不是。
        if token[0] != 0x30:
            raise ValueError(f"token 不是 SEQUENCE（tag=0x{token[0]:02x}）")
        _, _, end = _read_tlv(token, 0)
        if end != len(token):
            raise ValueError(f"token 后有 {len(token) - end} 字节多余数据")

    return PKI_STATUS.get(status, f"unknown({status})"), token


# ---------------------------------------------------------------------------
# 锚定记录
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Anchor:
    """一次外部时间戳锚定的结果。

    注意两个时间的语义差别，不要混用：
      submitted_at —— 本机墙钟。不可信，仅供运维排查。
      gen_time     —— TSA 在 token 内签名的时间。这才是证据。
                      未做验证时为 None，因为它藏在签名结构里，
                      不验签就读出来的值没有意义。
    """
    epoch_id: int
    anchored_hash: str
    tsa_url: str
    status: str
    submitted_at: str
    token_b64: str | None = None
    gen_time: str | None = None
    error: str | None = None
    # eIDAS 合格状态。见下方 DEFAULT_TSAS 的警告——这不是技术字段，是法律字段。
    # 关键在于必须记录*盖戳当时*的状态：合格资质可被暂停或撤销，验证时
    # 再去查已经晚了。这正是 TraceGuard 的 point-in-time 问题出现在信任层。
    #
    # 三值语义，与 verified_at_write 一致，不要用真值判断糊过去：
    #   True  —— 查过了，盖戳当时在 EU 可信列表上且状态为 granted
    #   False —— 查过了，不合格（不在列表上／状态非 granted／早于 eIDAS 适用日）
    #   None  —— **没查**（没给快照／没装依赖／该国列表当次构建时取不到）
    # 把"没查"记成"不合格"等于凭空造一个法律结论；把"确实不在列表上"
    # 记成"没查"等于放弃一个本可确定的事实。两者都不接受。
    #
    # ⚠ 本组字段不在**本** epoch 的 epoch_hash 里，也不可能在：合格状态要
    #   拿到 token（TSA 签名证书在里面）之后才算得出来，而 epoch_hash 是被
    #   盖戳的**输入**，盖完再回写会让刚取回的时间戳当场失效——tsa_token
    #   当年踩的就是这个坑。
    #
    #   保护它的办法是往后挪一格：Ledger.attach_anchor() 把这组值排队，
    #   下一次 seal_epoch() 写进**下一个** epoch 的被哈希体，于是它随下一次
    #   锚定的时间戳一起被覆盖（issue #3）。因此：
    #     · 走 attach_anchor + 再封一个 epoch 并锚定 → 受保护，改了查得出来
    #     · 只拿着这个 Anchor 对象不往下走          → 仍然只是一项声明
    #   两种状态的区别由 Ledger.unbound_anchor_count() 报出来，见 docs/eutl.md。
    tsa_qualified: bool | None = None
    eutl_ref: str | None = None          # EU 可信列表条目标识 "国别:列表序号:序号"
    qualified_checked_at: str | None = None
    qualified_reason: str | None = None  # 为什么是这个结论，尤其是 None 时
    # 判定依据的那份 EUTL 快照的摘要。issue #3 把它一并绑进下一个 epoch 的
    # 被哈希体：判定是相对某一份列表做出的，不指明是哪一份就无从复核。
    eutl_snapshot_sha256: str | None = None
    # 写入时是否做过「这个 token 确实盖的是我提交的东西」的检查。
    #   True  —— 装了 [tsa]，messageImprint 与 nonce 回显都对上了
    #   False —— 检查跑了但没对上。响应被替换或 TSA 有问题，这个 anchor 不可用
    #   None  —— 没装 [tsa]，没检查。token 照常存下，但你不知道它盖的是什么
    verified_at_write: bool | None = None

    @property
    def ok(self) -> bool:
        return (self.status in ("granted", "grantedWithMods")
                and bool(self.token_b64)
                # 明确写成 is not False：None（没检查）不阻断，False（检查没过）阻断。
                # 这两者在这里的语义差别很大，不能靠真值判断糊过去。
                and self.verified_at_write is not False)

    def token_bytes(self) -> bytes:
        return base64.b64decode(self.token_b64) if self.token_b64 else b""

    def write_token(self, path: str) -> str:
        """落盘为标准 .tsr，供 `openssl ts -verify` 使用。"""
        with open(path, "wb") as f:
            f.write(self.token_bytes())
        return path


# ⚠ 以下三家均为技术上合规的 RFC 3161 TSA，但**都不是** eIDAS QTSP，
#   未列入 EU 可信列表。后果具体而明确：
#     eIDAS 第 41(1) 条：非合格时间戳不得仅因电子形式而被否定证据资格 —— 仍可举证。
#     eIDAS 第 41(2) 条：只有*合格*时间戳享有时间准确性与数据完整性的法律推定，
#                        举证责任因此倒置给质疑方。
#   用非合格 TSA，举证责任留在你这边；用合格 TSA，留在对方那边。
#   打算走 Article 12 合规叙事时，必须换成 EU 可信列表上的 QTSP：
#     https://eidas.ec.europa.eu/efda/trust-services/
#   下面这组只适合开发、演示与内部完整性用途。
DEFAULT_TSAS = (
    "https://freetsa.org/tsr",
    "http://timestamp.digicert.com",
    "http://timestamp.sectigo.com",
)


def _inspect_token(token: bytes) -> tuple[str, int | None]:
    """从 token 里读出 messageImprint 与 nonce。需要 asn1crypto。

    这是软依赖：没装 [tsa] 时调用方跳过整个检查。刻意不在这里手搓
    CMS 解析——写入路径的零依赖承诺不能靠自造 ASN.1 解析器来维持，
    那等于用一个更大的风险换一个更小的。
    """
    from asn1crypto import cms, tsp

    sd = cms.ContentInfo.load(token)["content"]
    tst = tsp.TSTInfo.load(sd["encap_content_info"]["content"].contents)
    # nonce 是可选字段；缺失时 asn1crypto 给出 VOID，.native 为 None
    return tst["message_imprint"]["hashed_message"].native.hex(), tst["nonce"].native


def _signer_cert_and_gentime(token: bytes):
    """从 token 里取出签名证书的 DER 与 genTime。需要 asn1crypto。

    取签名者用 issuer+serial 配对，不是只比 serial —— 序列号只在同一个
    issuer 下唯一。verify.py 里犯过这个错（配不上时回退到 certs[0]，
    也就是拿一张签名者从未声称过的证书去验签），这里不重犯：配不上就
    返回 None，让调用方记成"未查"。
    """
    from asn1crypto import cms, tsp

    sd = cms.ContentInfo.load(token)["content"]
    tst = tsp.TSTInfo.load(sd["encap_content_info"]["content"].contents)
    gen = tst["gen_time"].native

    sid = sd["signer_infos"][0]["sid"]
    want = key_id = None
    if sid.name == "issuer_and_serial_number":
        want = (sid.chosen["issuer"].dump(), sid.chosen["serial_number"].native)
    else:
        key_id = sid.chosen.native

    for c in sd["certificates"]:
        cert = c.chosen
        if want is not None:
            if (cert.issuer.dump(), cert.serial_number) == want:
                return cert.dump(), gen
        elif cert.key_identifier == key_id:
            return cert.dump(), gen
    return None, gen


def _cert_facts(cert_der: bytes):
    """把签名证书拆成 eutl.CertFacts。需要 cryptography。"""
    import hashlib

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.x509.oid import NameOID

    from .eutl import CertFacts

    cert = x509.load_der_x509_certificate(cert_der)
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)

    def _one(oid):
        vs = cert.subject.get_attributes_for_oid(oid)
        return vs[0].value if vs else None

    return CertFacts(
        spki_sha256=hashlib.sha256(spki).hexdigest(),
        subject_der_sha256=hashlib.sha256(cert.subject.public_bytes()).hexdigest(),
        subject_str=cert.subject.rfc4514_string(),
        issuer_der_sha256=hashlib.sha256(cert.issuer.public_bytes()).hexdigest(),
        country=_one(NameOID.COUNTRY_NAME),
        organization=_one(NameOID.ORGANIZATION_NAME),
    ), cert


def _issued_by(child):
    """造一个回调：给定可信列表登记的 SPKI DER，验证 child 是否由它签发。

    只做签名验证，不做完整 RFC 5280 路径校验。实测数据支持这个取舍：
    列表里登记的要么是签时间戳的末端证书（路径长 0），要么是直接签发它的
    CA（路径长 1，意大利全部如此）。更长的路径本实现不尝试，会落到
    "未匹配"，这是**有意的保守**——宁可少判合格，不要多判。
    """
    def _cb(spki_der: bytes) -> bool:
        try:
            from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
            from cryptography.hazmat.primitives.serialization import load_der_public_key
            pub = load_der_public_key(spki_der)
            sig, tbs = child.signature, child.tbs_certificate_bytes
            algo = child.signature_hash_algorithm
            if isinstance(pub, rsa.RSAPublicKey):
                pub.verify(sig, tbs, padding.PKCS1v15(), algo)
            elif isinstance(pub, ec.EllipticCurvePublicKey):
                pub.verify(sig, tbs, ec.ECDSA(algo))
            else:
                return False
            return True
        except Exception:                        # noqa: BLE001
            return False
    return _cb


def check_qualified(token: bytes, snapshot):
    """判定这个 token 的 TSA 在**盖戳当时**是否为 eIDAS 合格服务。

    返回 eutl.Verdict。缺依赖、缺快照、该国列表取不到，一律给
    qualified=None（未查），绝不给 False —— 把"没查"记成"不合格"
    等于凭空造出一个法律结论，而这个结论会被写进不可变的记录里。

    关于 TS 119 615 PRO-4.7.4-06：规范要求在 genTime 与验证参考时刻各判
    一次、两者不一致即 PROCESS_FAILED。写入时这两个时刻相差毫秒，必然
    一致，所以这里只判一次。差异会在**以后**出现——那正是本字段存在的
    理由：以后再判，判的是那时的列表，答案已经不是当时的答案了。
    """
    from .eutl import Snapshot, Verdict

    if snapshot is None:
        return Verdict(None, None, "未提供 EUTL 快照，未做合格性判定")
    try:
        snap = snapshot if isinstance(snapshot, Snapshot) else Snapshot.load(str(snapshot))
    except Exception as e:                       # noqa: BLE001
        return Verdict(None, None, f"EUTL 快照不可用：{type(e).__name__}: {e}")

    try:
        cert_der, gen = _signer_cert_and_gentime(token)
    except ImportError:
        return Verdict(None, None, "未安装 [tsa]，取不到签名证书，未做合格性判定")
    except Exception as e:                       # noqa: BLE001
        return Verdict(None, None, f"token 解析失败：{type(e).__name__}: {e}")
    if cert_der is None:
        return Verdict(None, None, "token 内找不到 SignerInfo 声称的签名证书，未做判定")
    if gen is None:
        return Verdict(None, None, "token 内没有 genTime，未做判定")

    try:
        facts, cert = _cert_facts(cert_der)
    except ImportError:
        return Verdict(None, None, "未安装 [tsa]，无法解析证书，未做合格性判定")
    except Exception as e:                       # noqa: BLE001
        return Verdict(None, None, f"证书解析失败：{type(e).__name__}: {e}")

    if gen.tzinfo is None:
        gen = gen.replace(tzinfo=timezone.utc)
    return snap.qualified_at(facts, gen, verify_issued_by=_issued_by(cert))


def _verify_at_write(token: bytes, expected_hash: str,
                     nonce: int | None) -> tuple[bool | None, str | None]:
    """写入时的最小校验：这个 token 盖的确实是我提交的东西吗？

    返回 (verified, error)。verified 为 None 表示没装 [tsa]，跳过。

    检查的是 messageImprint 与 nonce 回显，不是签名。这两项针对的是
    「响应在路上被换掉了」——三家默认 TSA 里有两家是明文 http，
    而写入路径原先对返回的 token 不做任何检查，一个盖了别的哈希的
    合法 token 会被照单存下，直到几个月后审计才暴露，那时已经补不回来。

    完整验证（签名 + 证书链）仍然要走 verify.verify_token，需要信任根。
    这里只是把「几个月后才发现」缩短成「当场发现」。
    """
    try:
        imprint, echoed = _inspect_token(token)
    except ImportError:
        return None, None                        # 没装 [tsa]：跳过，不算失败
    except Exception as e:                       # noqa: BLE001
        return False, f"写入时校验：token 解析失败 {type(e).__name__}: {e}"

    if imprint != expected_hash:
        return False, (f"写入时校验：token 盖的不是我们提交的哈希"
                       f"（token 内 {imprint[:16]}… ≠ 提交 {expected_hash[:16]}…）")
    if nonce is not None and echoed != nonce:
        return False, (f"写入时校验：nonce 回显不符（收到 {echoed}，发出 {nonce}）"
                       f"——响应可能被替换或重放")
    return True, None


def anchor_hash(hex_hash: str, tsa_url: str, *, timeout: float = 10.0,
                nonce: int | None = None, epoch_id: int = -1,
                eutl=None) -> Anchor:
    """把一个十六进制哈希提交给 TSA 取回时间戳 token。

    失败不抛异常，返回带 error 的 Anchor。理由见 AnchorQueue 的注释：
    TSA 不可用绝不能阻塞生产决策路径。

    装了 tg-attest[tsa] 时，返回前会顺手校验 messageImprint 与 nonce 回显，
    结果记在 verified_at_write 上。没装就跳过，功能不受影响。

    eutl 传入 EUTL 快照（eutl.Snapshot 或快照文件路径）时，额外判定这家
    TSA 在**盖戳当时**是否为 eIDAS 合格服务，结果记在 tsa_qualified /
    eutl_ref / qualified_checked_at 上。不传就是三个 None（未查）。
    快照怎么来见 eutl_build.build_snapshot()；查询本身零依赖、纯索引查找，
    不会在热路径上发网络请求。
    """
    digest = bytes.fromhex(hex_hash)
    if nonce is None:
        # 随机 nonce。原先是 sha256(digest + b"nonce")[:8]，从 digest 确定性
        # 推导——任何知道 digest 的人都能算出 nonce，防重放能力为零。
        # RFC 3161 §2.4.1 要求 nonce 不可预测，配合下面的回显校验才有意义。
        nonce = secrets.randbits(64)
    req = urllib.request.Request(
        tsa_url, data=build_tsq(digest, nonce=nonce),
        headers={"Content-Type": "application/timestamp-query",
                 "User-Agent": "tg-attest/1"},
    )
    base = dict(epoch_id=epoch_id, anchored_hash=hex_hash, tsa_url=tsa_url,
                submitted_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            status, token = parse_tsr(r.read())
    except Exception as e:                       # noqa: BLE001 - 任何失败都要降级
        return Anchor(status="error", error=f"{type(e).__name__}: {e}", **base)

    if token is None:
        return Anchor(status=status, **base)

    verified, verr = _verify_at_write(token, hex_hash, nonce)
    if verified is False:
        log.error("anchor at %s failed write-time verification: %s", tsa_url, verr)

    # 合格性判定。刻意放在写入时而不是验证时：合格资质会被暂停、撤销，
    # TSP 每轮换一次密钥就是列表里一条状态时间线独立的新条目。以后再查，
    # 查到的是那时的列表，回答的是另一个问题。
    q = check_qualified(token, eutl)
    if q.qualified is False:
        log.info("anchor at %s: TSA 非 eIDAS 合格服务 —— %s", tsa_url, q.reason)

    return Anchor(status=status,
                  token_b64=base64.b64encode(token).decode(),
                  verified_at_write=verified,
                  error=verr,
                  tsa_qualified=q.qualified,
                  eutl_ref=q.ref,
                  qualified_checked_at=q.checked_at,
                  qualified_reason=q.reason,
                  eutl_snapshot_sha256=q.snapshot_sha256,
                  **base)


class AnchorQueue:
    """待锚定队列。

    关键性质（这条能省掉大量成本和可用性依赖）：
        epoch 根之间是串链的，所以锚定 epoch N 就同时给 N 之前所有 epoch
        的存在时间设了上界。**不需要每个 epoch 都锚。**
        TSA 挂了就排队，下次成功的那一次会把欠账一并覆盖。

    实践建议：高频写入按小时封 epoch，按天锚定一次即可。真正需要逐条
    锚定的只有单笔金额极大或强监管的决策，用 force 单独处理。
    """

    def __init__(self, tsa_urls: tuple[str, ...] = DEFAULT_TSAS, *, eutl=None) -> None:
        self.tsa_urls = tsa_urls
        self.pending: list[tuple[int, str]] = []
        self.anchors: list[Anchor] = []
        self.eutl = eutl

    def enqueue(self, epoch_id: int, epoch_hash: str) -> None:
        self.pending.append((epoch_id, epoch_hash))

    def flush(self, *, timeout: float = 10.0) -> Anchor | None:
        """锚定队列中最新的一个 epoch；成功则整队清空（被上界覆盖）。"""
        if not self.pending:
            return None
        epoch_id, ehash = self.pending[-1]
        for url in self.tsa_urls:
            a = anchor_hash(ehash, url, timeout=timeout, epoch_id=epoch_id,
                            eutl=self.eutl)
            if a.ok:
                self.anchors.append(a)
                covered = [e for e, _ in self.pending]
                self.pending.clear()
                # 库不 print。调用方要展示就读返回值，要日志就配 logging。
                log.info("anchored epoch %s at %s — also covers epochs %s",
                         epoch_id, url, covered)
                return a
            self.anchors.append(a)
        return None                              # 全部 TSA 失败，保留队列下次重试


# ---------------------------------------------------------------------------
# 验证路径（需要额外依赖，刻意与写入路径隔离）
# ---------------------------------------------------------------------------

VERIFY_HINT = """
审计方验证有两条路，都不需要安装 tg-attest：

  路线 A（推荐给监管/审计，零信任）——标准 openssl：
      openssl ts -verify -digest <epoch_hash> \\
          -in epoch_007.tsr -token_in \\
          -CAfile tsa_chain.pem

  路线 B（程序化）——pip install tg-attest[tsa]，内部使用
      cryptography + asn1crypto 校验 CMS 签名、证书链、
      以及 messageImprint 与 epoch_hash 是否一致。

刻意不把验证逻辑手写进本模块：CMS + X.509 链校验手搓等于自造漏洞，
而这是一个以可信为卖点的产品，自造的密码学是最贵的技术债。
"""

# 打包时从这里删掉了两个东西，记在这里免得日后有人再加回来：
#
#   verify_token()  —— 只比对 messageImprint、返回 signature_verified=False。
#     与 verify.verify_token() 同名而能力严格更弱，留着迟早有人 import 错；
#     而且它在本应零依赖的写入路径模块里 import 了 asn1crypto。
#     验证一律走 tg_attest.verify。
#
#   selftest_against_openssl() —— 与 openssl ts -query 逐字节比对。
#     这条断言是本模块唯一重要的正确性证明，但它属于测试，不属于运行时；
#     现在由 tests/test_tsq.py 持有，也就顺带把 subprocess 移出了发布包。
