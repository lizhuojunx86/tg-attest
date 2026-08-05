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
import hashlib
import urllib.request
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone

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
    tag = buf[i]
    i += 1
    n = buf[i]
    i += 1
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(buf[i:i + k], "big")
        i += k
    return tag, buf[i:i + n], i + n


PKI_STATUS = {0: "granted", 1: "grantedWithMods", 2: "rejection",
              3: "waiting", 4: "revocationWarning", 5: "revocationNotification"}


def parse_tsr(tsr: bytes) -> tuple[str, bytes | None]:
    """从 TimeStampResp 中取出状态与 TimeStampToken（DER）。

    只解析结构、不验签。验签是 verify_token() 的事，且需要额外依赖。
    """
    _, body, _ = _read_tlv(tsr, 0)                 # TimeStampResp SEQUENCE
    _, status_info, after = _read_tlv(body, 0)     # PKIStatusInfo
    _, status_bytes, _ = _read_tlv(status_info, 0)
    status = int.from_bytes(status_bytes, "big")
    token = body[after:] if after < len(body) else None
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
    tsa_qualified: bool | None = None
    eutl_ref: str | None = None          # EU 可信列表条目标识
    qualified_checked_at: str | None = None

    @property
    def ok(self) -> bool:
        return self.status in ("granted", "grantedWithMods") and bool(self.token_b64)

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


def anchor_hash(hex_hash: str, tsa_url: str, *, timeout: float = 10.0,
                nonce: int | None = None, epoch_id: int = -1) -> Anchor:
    """把一个十六进制哈希提交给 TSA 取回时间戳 token。

    失败不抛异常，返回带 error 的 Anchor。理由见 AnchorQueue 的注释：
    TSA 不可用绝不能阻塞生产决策路径。
    """
    digest = bytes.fromhex(hex_hash)
    if nonce is None:
        nonce = int.from_bytes(hashlib.sha256(digest + b"nonce").digest()[:8], "big")
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
        return Anchor(status=status,
                      token_b64=base64.b64encode(token).decode() if token else None,
                      **base)
    except Exception as e:                       # noqa: BLE001 - 任何失败都要降级
        return Anchor(status="error", error=f"{type(e).__name__}: {e}", **base)


class AnchorQueue:
    """待锚定队列。

    关键性质（这条能省掉大量成本和可用性依赖）：
        epoch 根之间是串链的，所以锚定 epoch N 就同时给 N 之前所有 epoch
        的存在时间设了上界。**不需要每个 epoch 都锚。**
        TSA 挂了就排队，下次成功的那一次会把欠账一并覆盖。

    实践建议：高频写入按小时封 epoch，按天锚定一次即可。真正需要逐条
    锚定的只有单笔金额极大或强监管的决策，用 force 单独处理。
    """

    def __init__(self, tsa_urls: tuple[str, ...] = DEFAULT_TSAS) -> None:
        self.tsa_urls = tsa_urls
        self.pending: list[tuple[int, str]] = []
        self.anchors: list[Anchor] = []

    def enqueue(self, epoch_id: int, epoch_hash: str) -> None:
        self.pending.append((epoch_id, epoch_hash))

    def flush(self, *, timeout: float = 10.0) -> Anchor | None:
        """锚定队列中最新的一个 epoch；成功则整队清空（被上界覆盖）。"""
        if not self.pending:
            return None
        epoch_id, ehash = self.pending[-1]
        for url in self.tsa_urls:
            a = anchor_hash(ehash, url, timeout=timeout, epoch_id=epoch_id)
            if a.ok:
                self.anchors.append(a)
                covered = [e for e, _ in self.pending]
                self.pending.clear()
                a = Anchor(**{**asdict(a)})
                print(f"  锚定 epoch {epoch_id} @ {url} — "
                      f"同时覆盖 epoch {covered}")
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


def verify_token(token_der: bytes, expected_hash: str,
                 ca_file: str | None = None) -> dict:
    """校验 token 并取出 TSA 签名时间。需要 tg-attest[tsa] 附加依赖。"""
    try:
        from asn1crypto import cms, tsp        # noqa: F401
    except ImportError as e:
        raise RuntimeError(
            "verify_token 需要附加依赖：pip install tg-attest[tsa]\n" + VERIFY_HINT
        ) from e

    ci = cms.ContentInfo.load(token_der)
    signed = ci["content"]
    tst = tsp.TSTInfo.load(signed["encap_content_info"]["content"].native)
    imprint = tst["message_imprint"]["hashed_message"].native.hex()
    if imprint != expected_hash:
        raise ValueError(f"messageImprint 不匹配：token 内 {imprint[:16]}… "
                         f"≠ 期望 {expected_hash[:16]}…")
    return {
        "gen_time": tst["gen_time"].native.isoformat(),
        "serial": str(tst["serial_number"].native),
        "policy": tst["policy"].native,
        "message_imprint": imprint,
        "signature_verified": False,   # 链校验需 ca_file，见路线 A
        "note": "签名与证书链校验请走 openssl ts -verify（见 VERIFY_HINT）",
    }


# ---------------------------------------------------------------------------
# 自检
# ---------------------------------------------------------------------------

def selftest_against_openssl() -> bool:
    """把手写 DER 与 openssl ts -query 的输出逐字节比对。

    这是本模块唯一重要的正确性证明：如果字节与 openssl 一致，
    那么任何能接受 openssl 请求的 TSA 都能接受我们的请求。
    """
    import subprocess, tempfile, os
    payload = b"tg-attest selftest"
    digest = hashlib.sha256(payload).digest()
    with tempfile.TemporaryDirectory() as d:
        f = os.path.join(d, "in.bin")
        open(f, "wb").write(payload)
        ref = subprocess.run(
            ["openssl", "ts", "-query", "-data", f, "-sha256", "-cert",
             "-no_nonce"], capture_output=True, check=True).stdout
    ours = build_tsq(digest, nonce=None, cert_req=True)
    if ours != ref:
        print(f"  ✗ 不匹配\n    ours={ours.hex()}\n    ossl={ref.hex()}")
        return False
    print(f"  ✓ 与 openssl ts -query 逐字节一致（{len(ours)} bytes）")
    return True
