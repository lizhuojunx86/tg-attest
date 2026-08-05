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
from dataclasses import dataclass, field
from datetime import timezone

from asn1crypto import cms, tsp, x509 as a_x509
from cryptography import x509 as c_x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa

EKU_TIMESTAMPING = "1.3.6.1.5.5.7.3.8"
_HASH = {"sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512,
         "sha1": hashes.SHA1}


@dataclass
class VerifyResult:
    ok: bool
    checks: dict = field(default_factory=dict)   # 每一环的独立结论
    gen_time: str | None = None
    tsa_subject: str | None = None
    errors: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        lines = [f"{'通过' if self.ok else '失败'}"]
        for k, v in self.checks.items():
            lines.append(f"  {'✓' if v is True else '✗' if v is False else '·'} {k}"
                         + (f" — {v}" if not isinstance(v, bool) else ""))
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
    h = _HASH.get(algo, hashes.SHA256)()
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


def verify_token(token_der: bytes, expected_hash: str,
                 ca_bundle: bytes | None = None) -> VerifyResult:
    """校验一个 RFC 3161 TimeStampToken。

    ca_bundle 为 None 时跳过证书链校验，其余检查照做，结果标记为
    ok=False——刻意不允许「没有信任根也算通过」，那是最常见的误用。
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
        sid = si["sid"]
        signer = next(
            (c for c in certs
             if (sid.name == "issuer_and_serial_number"
                 and c.serial_number == sid.chosen["serial_number"].native)
             or (sid.name == "subject_key_identifier"
                 and c.key_identifier == sid.chosen.native)),
            certs[0] if certs else None)
        if signer is None:
            r.errors.append("token 内没有签名证书（请求时应设 certReq=True）")
            return r
        r.tsa_subject = signer.subject.human_friendly

        # 3. RFC 3161 §2.3：签名证书必须带 timeStamping EKU，且该扩展为
        #    critical、且是唯一的 EKU。这条常被略过，但它正是防止拿一张
        #    普通 TLS 证书来冒充 TSA 的关键。
        eku = signer.extended_key_usage_value
        ekus = [u.dotted for u in eku] if eku else []
        crit = any(e["extn_id"].dotted == "2.5.29.37" and e["critical"].native
                   for e in signer["tbs_certificate"]["extensions"])
        r.checks["EKU 仅含 timeStamping"] = (ekus == [EKU_TIMESTAMPING])
        r.checks["EKU 扩展为 critical"] = crit

        # 4. signedAttrs 里的 message-digest 必须等于 eContent 的哈希
        attrs = si["signed_attrs"]
        md = next((a["values"][0].native for a in attrs
                   if a["type"].native == "message_digest"), None)
        digest_algo = si["digest_algorithm"]["algorithm"].native
        want = hashlib.new(digest_algo, econtent).digest()
        r.checks["signedAttrs.message-digest 匹配内容"] = (md == want)

        # 5. 验签：注意签名覆盖的是 SET OF 重标签后的 signedAttrs，
        #    不是 [0] IMPLICIT 的原始字节。这里错了会静默验不过。
        sig_algo = si["signature_algorithm"].hash_algo
        r.checks["TSA 签名有效"] = _verify_sig(
            _pubkey(signer), si["signature"].native,
            attrs.untag().dump(), sig_algo)

        # 6. 证书链
        if ca_bundle is None:
            r.checks["证书链校验"] = "已跳过（未提供 ca_bundle）"
            r.errors.append("未提供信任根，结论不可用于合规举证")
        else:
            anchors = _load_anchors(ca_bundle)
            r.checks["证书链至可信根"] = _chain_ok(signer, certs, anchors, gen)

        r.ok = all(v is True for v in r.checks.values())
    except Exception as e:                       # noqa: BLE001
        r.errors.append(f"{type(e).__name__}: {e}")
    return r


def _chain_ok(leaf, intermediates, anchors, at_time) -> bool:
    """朴素路径构建：逐级找签发者，验签 + 校验有效期。

    刻意不做 CRL/OCSP 撤销检查——离线验证场景下拿不到，而且时间戳的
    正确姿势是看『签名时刻证书是否有效』，需要配合 TSA 的存档 CRL。
    生产环境请补 CAdES-A / 长期保存格式。
    """
    pool = {c.subject.sha256: c for c in list(intermediates) + list(anchors)}
    cur, seen = leaf, set()
    for _ in range(8):
        if cur.self_signed in ("maybe", "yes") and any(
                cur.sha256 == a.sha256 for a in anchors):
            return True
        issuer = pool.get(cur.issuer.sha256)
        if issuer is None or issuer.sha256 in seen:
            return False
        seen.add(issuer.sha256)
        nb, na = (issuer["tbs_certificate"]["validity"]["not_before"].native,
                  issuer["tbs_certificate"]["validity"]["not_after"].native)
        if not (nb <= at_time <= na):
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
    from record import hash_obj, verify_inclusion, EpochSeal

    r = VerifyResult(ok=False)
    try:
        rec, epoch = bundle["record"], bundle["epoch"]

        r.checks["记录内容哈希自洽"] = (
            hash_obj(rec) == bundle["record_hash"])
        r.checks["Merkle 包含证明有效"] = verify_inclusion(
            bundle["record_hash"], [tuple(p) for p in bundle["proof"]],
            epoch["merkle_root"])

        seal = EpochSeal(**{**epoch, "tsa_token": None})
        ehash = seal.epoch_hash()

        tok = bundle.get("tsa_token")
        if not tok:
            r.errors.append("披露包内无时间戳 token，无法证明存在时刻")
            return r

        tr = verify_token(base64.b64decode(tok), ehash, ca_bundle)
        r.checks.update({f"时间戳/{k}": v for k, v in tr.checks.items()})
        r.errors += tr.errors
        r.gen_time, r.tsa_subject = tr.gen_time, tr.tsa_subject
        r.ok = all(v is True for v in r.checks.values())
    except Exception as e:                       # noqa: BLE001
        r.errors.append(f"{type(e).__name__}: {e}")
    return r


def export_bundle(led, seq: int, path: str) -> str:
    """导出自包含披露包。写盘的是纯 JSON，不含任何本库特有格式。"""
    b = led.disclose(seq)
    b["tsa_token"] = b["epoch"].get("tsa_token")
    b["epoch"] = {**b["epoch"], "tsa_token": None}   # token 单独放，避免自指
    b["_verify"] = {
        "spec": "tg-attest/1",
        "chain": ["record→record_hash", "merkle proof→merkle_root",
                  "epoch_hash(excl. tsa_token)", "TSA messageImprint",
                  "TSA signature", "genTime"],
        "openssl": "openssl ts -reply -in epoch.tsr -token_in -text",
        "note": "信任根须由验证方独立获得，不得使用本包内提供的任何证书。",
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(b, f, ensure_ascii=False, indent=2, default=str)
    return path
