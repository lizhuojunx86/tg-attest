"""
tg-attest.verify — 验证路径。属于 `pip install tg-attest[tsa]` 附加依赖。

与写入路径隔离的理由见 anchor.py。这里可以放心用 asn1crypto + cryptography。

本模块回答一个问题，且只回答这一个：
    「这条决策记录，在时刻 T 之前就已经以这个形态存在。」

证明链条（verify_bundle 逐环校验，任一环断则整体失败）：
    record 内容 → record_hash
                → Merkle 包含证明 → merkle_root
                → epoch_hash（排除 tsa_token 的规范化哈希）
                → TSA token 内的 messageImprint
                → TSA 签名（signedAttrs + 证书链 + timeStamping EKU）
                → genTime

一条关于信任根的硬约束：
    信任根不能来自 bundle 自身。如果把 CA 证书打进包里，伪造者会连
    自己的根一起打进去，整个证明退化为同义反复。ca_bundle 必须由
    验证方独立获得——系统信任库、或从 QTSP 官网/EU 可信列表另行取得。
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import timezone

from asn1crypto import cms, tsp
from asn1crypto import x509 as a_x509
from cryptography import x509 as c_x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from .record import EpochSeal, hash_obj, profile_violations, verify_inclusion

EKU_TIMESTAMPING = "1.3.6.1.5.5.7.3.8"
_HASH = {"sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512,
         "sha1": hashes.SHA1}


# ---------------------------------------------------------------------------
# 必需检查清单
# ---------------------------------------------------------------------------
# 这两个常量是本模块最重要的东西，比下面任何一段解析代码都重要。
#
# 之前的判定是对运行时攒出来的 checks 字典做 all()。那个形状有一个要命的
# 性质：**检查项越少越容易通过**。解析在第三步抛异常，前两项为 True，
# all() 就是 True。攒不出检查项的极端情况下 all({}) 更是直接为 True。
# 也就是说，代码走得越少、失败得越早，结论越倾向于「通过」。
# 一个验证工具不能有这种形状。
#
# 改成静态清单之后，判定的形状反过来了：ok 要求这份清单**逐项到齐且为 True**。
# 缺项就是失败，而不是「没检查所以不算数」。以后再往下面加检查步骤，
# 只要忘了在这里注册，test_required_checks.py 会当场抓住。
#
# 顺序即证明链的顺序，不要随便调。
TOKEN_REQUIRED_CHECKS = (
    "eContentType 为 id-ct-TSTInfo",
    "messageImprint 匹配 epoch_hash",
    "EKU 仅含 timeStamping",
    "EKU 扩展为 critical",
    "signedAttrs.message-digest 匹配内容",
    "TSA 签名有效",
    "证书链至可信根",
)

BUNDLE_REQUIRED_CHECKS = (
    "记录内容哈希自洽",
    # 完整性档案。哈希链证明的是「没被改过」，不是「当初记全了」——
    # 一条 evidence 为空的记录同样能被完美地签名和锚定。这一项把
    # 「字段缺失」从不可见变成一条验证失败。
    "记录满足所声明的完整性档案",
    "Merkle 包含证明有效",
    *(f"时间戳/{c}" for c in TOKEN_REQUIRED_CHECKS),
)


@dataclass
class VerifyResult:
    ok: bool
    checks: dict = field(default_factory=dict)   # 每一环的独立结论
    gen_time: str | None = None
    tsa_subject: str | None = None
    errors: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)   # 必需但没跑到的检查
    # 记录方的声明，**不受时间戳保护**，因此与 checks 分开放。
    # 混进 checks 会让人以为它和其他检查项一样是被验证过的东西。
    attestations: dict = field(default_factory=dict)

    def conclude(self, required: tuple[str, ...]) -> "VerifyResult":
        """按必需清单收敛出最终结论。

        ok 成立当且仅当：required 里每一项都存在、都为 True，且 errors 为空。

        「缺项算失败」这条是整个改动的重点。旧版本用 all(checks.values())，
        缺项等于没有反对票，于是解析越早失败越容易「通过」——
        实测过：把 tsa_token 换成一段垃圾，ok=True。

        验证工具的失败方向必须是拒绝，不能是放行。
        """
        self.missing = [c for c in required if c not in self.checks]
        self.ok = (not self.missing
                   and all(self.checks.get(c) is True for c in required)
                   and not self.errors)
        return self

    def __str__(self) -> str:
        lines = [f"{'通过' if self.ok else '失败'}"]
        for k, v in self.attestations.items():
            q = v.get("tsa_qualified")
            mark = {True: "是", False: "否", None: "未查"}.get(q, "未查")
            lines.append(f"  · {k}：{mark}"
                         + (f"（{v.get('eutl_ref')}）" if v.get("eutl_ref") else ""))
        for k, v in self.checks.items():
            lines.append(f"  {'✓' if v is True else '✗' if v is False else '·'} {k}"
                         + (f" — {v}" if not isinstance(v, bool) else ""))
        for m in self.missing:
            # 没跑到的必需检查要显式列出来。默默不显示，就又变回了
            # 「少一项检查等于少一票反对」的老问题——只不过这次是在人眼里。
            lines.append(f"  ? {m} — 必需检查未执行")
        for e in self.errors:
            lines.append(f"  ! {e}")
        if self.gen_time:
            lines.append(f"  TSA 签名时间：{self.gen_time}")
        return "\n".join(lines)


def _load_anchors(ca_pem: bytes) -> list[a_x509.Certificate]:
    out, buf, on = [], [], False
    for line in ca_pem.splitlines(keepends=True):
        if b"BEGIN CERTIFICATE" in line:
            on, buf = True, [line]
        elif b"END CERTIFICATE" in line and on:
            buf.append(line)
            out.append(a_x509.Certificate.load(
                base64.b64decode(b"".join(buf[1:-1]))))
            on = False
        elif on:
            buf.append(line)
    return out


def _pubkey(cert: a_x509.Certificate):
    return c_x509.load_der_x509_certificate(cert.dump()).public_key()


def _verify_sig(pub, sig: bytes, data: bytes, algo: str) -> bool:
    # 认不出的摘要算法一律判失败，不能默默按 SHA-256 试。
    # 原来是 _HASH.get(algo, hashes.SHA256)()，把「我不认识这个算法」
    # 悄悄变成了「那就当 SHA-256 吧」。绝大多数情况下它会验不过（安全），
    # 但那是靠运气——判定不该建立在「猜错了大概率会失败」上面。
    if algo not in _HASH:
        return False
    h = _HASH[algo]()
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            pub.verify(sig, data, padding.PKCS1v15(), h)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(sig, data, ec.ECDSA(h))
        else:
            return False
        return True
    except Exception:
        return False


EXT_EKU = "2.5.29.37"


def _find_signer(certs, sid):
    """按 SignerInfo.sid 在 token 所附证书里定位签名证书。找不到返回 None。

    两处比参考实现严：

      1. issuer_and_serial_number 要比对 issuer + serial 两项。
         原来只比 serial——而序列号只在单个签发者内唯一，
         不同 CA 完全可以签出同号证书。
      2. 找不到就是 None，不再退回 certs[0]。原来的兜底把
         「sid 指向的证书不在 token 里」这个格式错误变成了
         「那就用第一张吧」——用一张签名者没有声称过的证书去验签，
         验的已经不是同一件事了。

    单独抽出来是因为三家默认 TSA 都用 issuer_and_serial_number，
    subject_key_identifier 那条分支拿真 token 一次也走不到。
    """
    for c in certs:
        if sid.name == "issuer_and_serial_number":
            if (c.serial_number == sid.chosen["serial_number"].native
                    and c.issuer.sha256 == sid.chosen["issuer"].sha256):
                return c
        elif sid.name == "subject_key_identifier":
            if c.key_identifier is not None and c.key_identifier == sid.chosen.native:
                return c
    return None


def _eku_status(cert) -> tuple[bool, bool]:
    """(EKU 是否恰好只有 timeStamping, EKU 扩展是否为 critical)。

    单独抽出来是为了能拿合成证书直接打这两条。放在 verify_token 里
    只能靠一个完整的 CMS token 才碰得到，而「EKU 不是 critical 的证书」
    没有哪家真实 TSA 会签给你，于是这条检查在测试里一直是没被覆盖的。
    变异测试把这一点抓了出来：把这里的 and 改成 or，整套测试照样全绿。
    """
    eku = cert.extended_key_usage_value
    only_timestamping = [u.dotted for u in eku] == [EKU_TIMESTAMPING] if eku else False
    critical = any(e["extn_id"].dotted == EXT_EKU and e["critical"].native
                   for e in cert["tbs_certificate"]["extensions"])
    return only_timestamping, critical


def verify_token(token_der: bytes, expected_hash: str,
                 ca_bundle: bytes | None = None) -> VerifyResult:
    """校验一个 RFC 3161 TimeStampToken。

    ca_bundle 为 None 时跳过证书链校验，其余检查照做，结果标记为
    ok=False——刻意不允许「没有信任根也算通过」，那是最常见的误用。
    此时「证书链至可信根」会作为 missing 出现在结果里，而不是悄悄消失。
    """
    r = VerifyResult(ok=False)
    try:
        ci = cms.ContentInfo.load(token_der)
        sd = ci["content"]
        eci = sd["encap_content_info"]

        # 1. 内容类型必须是 TSTInfo，不能是别的被塞进来的东西
        r.checks["eContentType 为 id-ct-TSTInfo"] = (
            eci["content_type"].native == "tst_info")

        # eContent 必须取原始 DER 字节：signedAttrs 里的 message-digest 是对
        # 这段字节做的哈希。asn1crypto 的 .native 会自动解析成 dict，用它算
        # 哈希必然对不上——这是本模块最容易踩的一个坑。
        econtent = eci["content"].contents
        tst = tsp.TSTInfo.load(econtent)

        # 2. messageImprint 必须等于我们要证明的那个哈希
        imprint = tst["message_imprint"]["hashed_message"].native.hex()
        r.checks["messageImprint 匹配 epoch_hash"] = (imprint == expected_hash)
        gen = tst["gen_time"].native.astimezone(timezone.utc)
        r.gen_time = gen.isoformat()

        si = sd["signer_infos"][0]
        certs = [c.chosen for c in sd["certificates"]] if sd["certificates"] else []
        signer = _find_signer(certs, si["sid"])
        if signer is None:
            r.errors.append(
                "token 内找不到 SignerInfo.sid 指向的签名证书"
                "（请求时应设 certReq=True；或 sid 与所附证书不一致）")
            return r.conclude(TOKEN_REQUIRED_CHECKS)
        r.tsa_subject = signer.subject.human_friendly

        # 3. RFC 3161 §2.3：签名证书必须带 timeStamping EKU，且该扩展为
        #    critical、且是唯一的 EKU。这条常被略过，但它正是防止拿一张
        #    普通 TLS 证书来冒充 TSA 的关键。
        only_ts, eku_crit = _eku_status(signer)
        r.checks["EKU 仅含 timeStamping"] = only_ts
        r.checks["EKU 扩展为 critical"] = eku_crit

        # 4. signedAttrs 里的 message-digest 必须等于 eContent 的哈希
        attrs = si["signed_attrs"]
        md = next((a["values"][0].native for a in attrs
                   if a["type"].native == "message_digest"), None)
        digest_algo = si["digest_algorithm"]["algorithm"].native
        want = hashlib.new(digest_algo, econtent).digest()
        r.checks["signedAttrs.message-digest 匹配内容"] = (md == want)

        # 5. 验签：注意签名覆盖的是 SET OF 重标签后的 signedAttrs，
        #    不是 [0] IMPLICIT 的原始字节。这里错了会静默验不过。
        #
        #    signatureAlgorithm 不一定绑定哈希。FreeTSA 用 sha512_ecdsa，
        #    哈希写在算法 OID 里；DigiCert 和 Sectigo 用 rsassa_pkcs1v15，
        #    OID 里没有哈希，asn1crypto 的 .hash_algo 会直接抛 ValueError。
        #    RFC 5652 §5.3 规定这种情况下摘要算法取自 SignerInfo.digestAlgorithm。
        #    少了这个回退，三家默认 TSA 里有两家的 token 根本走不到验签这一步。
        try:
            sig_algo = si["signature_algorithm"].hash_algo
        except ValueError:
            sig_algo = digest_algo
        r.checks["TSA 签名有效"] = _verify_sig(
            _pubkey(signer), si["signature"].native,
            attrs.untag().dump(), sig_algo)

        # 6. 证书链
        if ca_bundle is None:
            # 不写进 checks。写一个字符串进去等于伪造了一条「跑过了」的记录，
            # 而这一项其实根本没跑。让它作为 missing 出现，结论才是诚实的。
            r.errors.append("未提供信任根，结论不可用于合规举证")
        else:
            anchors = _load_anchors(ca_bundle)
            if not anchors:
                # PEM 里一张证书都没解析出来，多半是传错了文件。
                # 这种情况下 _chain_ok 会一路 return False，但错因是「没有信任根」，
                # 不是「链验不过」，得说清楚，否则用户会去查错方向。
                r.errors.append("ca_bundle 里没有解析出任何证书")
            else:
                r.checks["证书链至可信根"] = _chain_ok(signer, certs, anchors, gen)
    except Exception as e:                       # noqa: BLE001
        r.errors.append(f"{type(e).__name__}: {e}")
    return r.conclude(TOKEN_REQUIRED_CHECKS)


def _valid_at(cert, at_time) -> bool:
    v = cert["tbs_certificate"]["validity"]
    return v["not_before"].native <= at_time <= v["not_after"].native


def _chain_ok(leaf, intermediates, anchors, at_time) -> bool:
    """朴素路径构建：逐级找签发者，验签 + 校验有效期。

    刻意不做 CRL/OCSP 撤销检查——离线验证场景下拿不到，而且时间戳的
    正确姿势是看『签名时刻证书是否有效』，需要配合 TSA 的存档 CRL。
    生产环境请补 CAdES-A / 长期保存格式。
    """
    pool = {c.subject.sha256: c for c in list(intermediates) + list(anchors)}
    # 叶子证书自身的有效期原本没查，只查了各级签发者的。后果是 genTime
    # 落在签名证书签发之前或过期之后都照样判通过——而「签名时刻证书有效」
    # 正是 RFC 3161 §2.4.1 对 TSA 的核心要求，也正是时间戳的全部意义。
    if not _valid_at(leaf, at_time):
        return False
    cur, seen = leaf, set()
    for _ in range(8):
        if cur.self_signed in ("maybe", "yes") and any(
                cur.sha256 == a.sha256 for a in anchors):
            return True
        issuer = pool.get(cur.issuer.sha256)
        if issuer is None or issuer.sha256 in seen:
            return False
        seen.add(issuer.sha256)
        if not _valid_at(issuer, at_time):
            return False
        if not _verify_sig(_pubkey(issuer), cur["signature_value"].native,
                           cur["tbs_certificate"].dump(),
                           cur["signature_algorithm"].hash_algo):
            return False
        if any(issuer.sha256 == a.sha256 for a in anchors):
            return True
        cur = issuer
    return False


# ---------------------------------------------------------------------------
# 端到端：从一条决策记录到一个被签名的时间
# ---------------------------------------------------------------------------

def verify_bundle(bundle: dict, ca_bundle: bytes | None = None) -> VerifyResult:
    """校验一个自包含披露包。这是审计方唯一需要调用的函数。"""
    r = VerifyResult(ok=False)
    try:
        rec, epoch = bundle["record"], bundle["epoch"]

        r.checks["记录内容哈希自洽"] = (
            hash_obj(rec) == bundle["record_hash"])

        # 记录自称遵循某个完整性档案，档案名参与哈希所以改不动。
        # 这里拿同一套规则离线复核一遍：声明了 eu-ai-act 却没有证据的记录，
        # 密码学上完美无缺，作为证据却是空的。
        pv = profile_violations(rec)
        r.checks["记录满足所声明的完整性档案"] = not pv
        r.errors += [f"完整性档案：{v}" for v in pv]

        r.checks["Merkle 包含证明有效"] = verify_inclusion(
            bundle["record_hash"], [tuple(p) for p in bundle["proof"]],
            epoch["merkle_root"])

        seal = EpochSeal(**{**epoch, "tsa_token": None})
        ehash = seal.epoch_hash()

        tok = bundle.get("tsa_token")
        if not tok:
            r.errors.append("披露包内无时间戳 token，无法证明存在时刻")
            return r.conclude(BUNDLE_REQUIRED_CHECKS)

        tr = verify_token(base64.b64decode(tok), ehash, ca_bundle)
        r.checks.update({f"时间戳/{k}": v for k, v in tr.checks.items()})
        r.errors += tr.errors
        r.gen_time, r.tsa_subject = tr.gen_time, tr.tsa_subject
        # 子结果的结论必须被继承，不能只把它的 checks 合进来重算一遍——
        # 那正是旧版本「子结果说失败、父结果算出通过」的来源。
        if not tr.ok and not r.errors:
            r.errors.append("时间戳校验未通过")
    except Exception as e:                       # noqa: BLE001
        r.errors.append(f"{type(e).__name__}: {e}")
    _report_attestation(bundle, r)
    _verify_binding(bundle, ca_bundle, r)
    return r.conclude(BUNDLE_REQUIRED_CHECKS)


def _verify_binding(bundle: dict, ca_bundle: bytes | None, r: "VerifyResult") -> None:
    """校验绑定 epoch：本 epoch 的锚定判定确实被下一个 epoch 的时间戳覆盖。

    包里带了 binding_epoch 才做。做三件事：
      1. binding_epoch 里那条判定说的确实是本 epoch 的那次锚定
         （anchored_hash 对得上本 epoch 的 epoch_hash，token 摘要对得上）
      2. binding_epoch 自己的 token 盖的确实是它自己的 epoch_hash
      3. 于是那条判定的任何一个字段被改动，第 2 步都会失败

    结果进 attestations 而不是 checks，理由和 #2 一样：是否合格是法律分类，
    不该决定一个披露包在技术上是否有效。用非合格 TSA 的包完全有效，
    只是举证责任在出具方那边。
    """
    be = bundle.get("binding_epoch")
    if not isinstance(be, dict):
        return
    out: dict = {"tsa_qualified": None, "eutl_ref": None}
    try:
        att = be.get("prev_anchor_attestation")
        if not att:
            out["reason"] = "binding_epoch 里没有锚定判定"
            r.attestations["⚠ 绑定校验"] = out
            return

        own = EpochSeal(**{**bundle["epoch"], "tsa_token": None}).epoch_hash()
        if att.get("anchored_hash") != own:
            out["reason"] = ("binding_epoch 里的判定指向的不是本 epoch"
                             f"（判定说 {str(att.get('anchored_hash'))[:16]}…，"
                             f"本 epoch 是 {own[:16]}…）")
            r.attestations["⚠ 绑定校验"] = out
            return

        tok = bundle.get("tsa_token")
        if tok and att.get("token_sha256"):
            if hashlib.sha256(base64.b64decode(tok)).hexdigest() != att["token_sha256"]:
                out["reason"] = "判定说的不是本包里这个 token"
                r.attestations["⚠ 绑定校验"] = out
                return

        btok = bundle.get("binding_tsa_token")
        if not btok:
            out["reason"] = "binding_epoch 没有 token，那条判定同样没被盖戳"
            r.attestations["⚠ 绑定校验"] = out
            return

        bhash = EpochSeal(**{**be, "tsa_token": None}).epoch_hash()
        btr = verify_token(base64.b64decode(btok), bhash, ca_bundle)
        r.attestations["eIDAS 合格状态（已被下一个 epoch 的时间戳覆盖）"] = {
            "tsa_qualified": att.get("tsa_qualified"),
            "eutl_ref": att.get("eutl_ref"),
            "checked_at": att.get("qualified_checked_at"),
            "eutl_snapshot_sha256": att.get("eutl_snapshot_sha256"),
            "binding_verified": btr.ok,
            "binding_gen_time": btr.gen_time,
            "reason": ("这条判定参与了 binding_epoch 的哈希，而该哈希被上面这个"
                       "时间戳签署，因此改动它会被查出来"
                       if btr.ok else
                       f"绑定时间戳未通过校验：{'; '.join(btr.errors) or '见 checks'}"),
        }
    except Exception as e:                       # noqa: BLE001
        out["reason"] = f"绑定校验失败：{type(e).__name__}: {e}"
        r.attestations["⚠ 绑定校验"] = out


def _report_attestation(bundle: dict, r: "VerifyResult") -> None:
    """把披露包里的 eIDAS 合格状态声明如实转述出来，**不当成检查项**。

    刻意不放进 checks，也刻意不进 BUNDLE_REQUIRED_CHECKS：
      · 它不受时间戳保护，与其他每一项检查的性质都不同；
      · 「是否合格」是法律分类，不该成为技术验证的通过条件。一个用非合格
        TSA 的包在技术上完全有效，只是举证责任在出具方那边（eIDAS 41(1)
        对 41(2)）。让它决定 ok，等于把两件事混为一谈。
    """
    a = bundle.get("eutl_attestation")
    if not isinstance(a, dict):
        return
    r.attestations["eIDAS 合格状态（记录方声明，未经本工具验证）"] = {
        "tsa_qualified": a.get("tsa_qualified"),
        "eutl_ref": a.get("eutl_ref"),
        "checked_at": a.get("qualified_checked_at"),
    }


def export_bundle(led, seq: int, path: str, *, allow_unanchored: bool = False,
                  anchor=None, include_binding: bool = False) -> str:
    """导出自包含披露包。写盘的是纯 JSON，不含任何本库特有格式。

    没有 tsa_token 的 epoch 默认拒绝导出。这种包在 verify_bundle 那边
    永远验不过（「披露包内无时间戳 token」），但导出时不说，使用者会以为
    自己手里有一份证据，直到交出去才发现它什么也证明不了。
    确实需要导出未锚定的包时显式传 allow_unanchored=True。
    """
    b = led.disclose(seq)
    b["tsa_token"] = b["epoch"].get("tsa_token")
    b["epoch"] = {**b["epoch"], "tsa_token": None}   # token 单独放，避免自指

    if not b["tsa_token"] and not allow_unanchored:
        raise ValueError(
            f"epoch {b['epoch']['epoch_id']} 没有时间戳 token，导出的包无法验证。"
            "先完成锚定，或显式传 allow_unanchored=True。")

    b["_verify"] = {
        "spec": "tg-attest/1",
        "chain": ["record→record_hash", "merkle proof→merkle_root",
                  "epoch_hash(excl. tsa_token)", "TSA messageImprint",
                  "TSA signature", "genTime"],
        "openssl": "openssl ts -reply -in epoch.tsr -token_in -text",
        "note": "信任根须由验证方独立获得，不得使用本包内提供的任何证书。",
    }
    if not b["tsa_token"]:
        b["_verify"]["warning"] = "未锚定：本包无时间戳，不能证明存在时刻。"

    # eIDAS 合格状态。传了 anchor 才写，且必须写清楚它不受时间戳保护——
    # 合格状态只有拿到 token 之后才算得出来，而 epoch_hash 是被盖戳的
    # *输入*，把它算进去会让刚取回的时间戳当场失效（不变量 5）。
    # 所以这是一项**声明**，不是一项证据。审计方要复核，就拿 eutl_ref
    # 自己去查可信列表；本包不提供、也不应提供那份列表。
    if anchor is not None and getattr(anchor, "tsa_qualified", None) is not None:
        b["eutl_attestation"] = {
            "tsa_qualified": anchor.tsa_qualified,
            "eutl_ref": anchor.eutl_ref,
            "qualified_checked_at": anchor.qualified_checked_at,
            "reason": anchor.qualified_reason,
            "_not_covered_by_timestamp": (
                "本节由记录方在盖戳时写入，不参与 epoch_hash，因此不受时间戳"
                "保护，可被事后修改而不留痕。要独立复核，用 eutl_ref 到 "
                "EU 可信列表自行查询，不要以本节为准。"),
        }

    # 绑定 epoch（issue #3）。本 epoch 的锚定判定被写在**下一个** epoch 的
    # 被哈希体里，所以要让审计方能自己验那条判定，包里必须带上下一个 epoch
    # 及其 token。默认不带：多一个 token 就多几 KB，而大多数披露只关心
    # 「这条记录当时存在」，不关心「盖戳的那家 TSA 当时合不合格」。
    if include_binding:
        nxt = next((e for e in led._epochs
                    if e.epoch_id == b["epoch"]["epoch_id"] + 1), None)
        if nxt is None or nxt.prev_anchor_attestation is None:
            raise ValueError(
                f"epoch {b['epoch']['epoch_id']} 的锚定判定还没有被任何 epoch "
                "哈希覆盖（下一个 epoch 不存在或不带判定）。再封存并锚定一个 "
                "epoch，或者不要传 include_binding=True。")
        b["binding_epoch"] = {**asdict(nxt), "tsa_token": None}
        b["binding_tsa_token"] = nxt.tsa_token
        b["_verify"]["binding"] = (
            "binding_epoch 的被哈希体里含有对本 epoch 那次锚定的判定，"
            "而 binding_epoch 自己被 binding_tsa_token 盖了戳。改动那条判定的"
            "任何字段都会让 binding_tsa_token 验不过。")

    with open(path, "w", encoding="utf-8") as f:
        # 不用 default=str。序列化不了的值应当当场抛错，而不是被悄悄
        # 转成字符串——那会让包里的内容和当初被哈希的内容对不上，
        # 而症状是几个月后审计时一句「记录内容哈希自洽 = False」。
        json.dump(b, f, ensure_ascii=False, indent=2)
    return path
