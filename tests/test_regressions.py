"""三个已修 fail-open 的具名回归测试。

每一个都对应一个曾经真实存在、且会让验证工具输出「通过」的缺陷。
名字里写明它防的是什么，因为回归测试在失败时唯一的作用就是让人
一眼看出「你把什么东西弄回去了」。

三个缺陷共同的形状：失败发生在检查之前，于是那项检查压根没跑，
而判定只看「跑了的都过了」。它们不是三个 bug，是同一个 bug 的三次显形。
结构性的修法见 tests/test_required_checks.py。
"""

from __future__ import annotations

import base64
import datetime as dt
import json

import pytest

from helpers import FIXTURES
from tg_attest.record import EpochSeal
from tg_attest.verify import (
    BUNDLE_REQUIRED_CHECKS,
    _chain_ok,
    _load_anchors,
    verify_bundle,
    verify_token,
)

RSA_TOKENS = json.loads((FIXTURES / "rsa_tsa_tokens.json").read_text(encoding="utf-8"))


# ===========================================================================
# 回归 1：空 checks 不得算作通过
# ===========================================================================

def test_regression_empty_checks_must_not_pass(bundle, ca_pem):
    """曾经：verify_bundle 用 all(checks.values()) 判定。

    token 解析一抛异常，时间戳那一侧一项检查都没产出，只剩记录层的两项，
    all() 返回 True，CLI 打印「通过」并退出 0。

    实测过的最小复现就是下面这行：把 tsa_token 换成一段垃圾的 base64。
    修法不是给这一处打补丁，是把判定改成静态必需清单（缺项即失败）。
    """
    bundle["tsa_token"] = base64.b64encode(b"this is not a CMS structure").decode()
    r = verify_bundle(bundle, ca_pem)

    assert r.ok is False, "垃圾 token 被判为通过——fail-open 回来了"
    assert r.errors
    assert r.missing, "时间戳侧一项都没跑到，missing 必须非空"
    # 记录层那两项确实是通过的。它们通过并不能让整体通过，这正是要点。
    assert r.checks["记录内容哈希自洽"] is True
    assert r.checks["Merkle 包含证明有效"] is True


def test_regression_empty_checks_must_not_pass_at_token_level(ca_pem):
    """同一个缺陷在 verify_token 这一层的形态：checks 为空字典。"""
    r = verify_token(b"", "ab" * 32, ca_pem)
    assert r.ok is False
    assert r.checks == {}
    assert r.errors


# ===========================================================================
# 回归 2：rsassa_pkcs1v15 的签名必须真的被验
# ===========================================================================

@pytest.fixture(params=sorted(RSA_TOKENS), ids=sorted(RSA_TOKENS))
def rsa_token(request) -> dict:
    return RSA_TOKENS[request.param]


def test_regression_rsassa_pkcs1v15_signature_actually_verified(rsa_token):
    """曾经：三家默认 TSA 里有两家从来没被验过签。

    DigiCert 和 Sectigo 用 rsassa_pkcs1v15，OID 里不绑定哈希，
    asn1crypto 的 si["signature_algorithm"].hash_algo 直接抛
    ValueError: Hash algorithm not known for rsassa_pkcs1v15。
    异常发生在验签之前，被 except 收进 errors，然后叠加回归 1，
    整体判定为「通过」。

    RFC 5652 §5.3：signatureAlgorithm 不绑定哈希时，摘要算法取自
    SignerInfo.digestAlgorithm。

    这里用的是真实的 DigiCert / Sectigo token，离线。
    """
    assert rsa_token["signature_algorithm"] == "rsassa_pkcs1v15", \
        "fixture 不是要测的那种 token，这个用例什么也没证明"

    r = verify_token(base64.b64decode(rsa_token["tsa_token"]),
                     rsa_token["epoch_hash"], None)

    assert "TSA 签名有效" in r.checks, "验签这一步根本没跑到"
    assert r.checks["TSA 签名有效"] is True
    assert not any("Hash algorithm not known" in e for e in r.errors), r.errors


def test_regression_rsa_token_tamper_still_rejected(rsa_token):
    """修兼容性不能顺手把安全性修没了：改一位仍须验不过。"""
    raw = bytearray(base64.b64decode(rsa_token["tsa_token"]))
    raw[-1] ^= 0xFF
    r = verify_token(bytes(raw), rsa_token["epoch_hash"], None)
    assert r.ok is False
    assert r.checks.get("TSA 签名有效") is not True


def test_regression_cross_tsa_root_must_fail():
    """交叉验证：用 A 家的根去验 B 家的 token，必须失败。

    这是「证书链真的被验了」的正面证据。如果链校验被跳过或被异常吞掉，
    这个用例会通过——而它通过就意味着任何人拿任何根都能验任何 token。

    三家两两组合全试一遍，含 FreeTSA 与两家 RSA TSA 的互验。
    """
    roots = {"freetsa": (FIXTURES / "freetsa_ca.pem").read_bytes()}
    tokens = {name: (base64.b64decode(t["tsa_token"]), t["epoch_hash"])
              for name, t in RSA_TOKENS.items()}

    # FreeTSA 的 token 从披露包里取
    b = json.loads((FIXTURES / "decision_0000.json").read_text(encoding="utf-8"))
    tokens["freetsa"] = (
        base64.b64decode(b["tsa_token"]),
        EpochSeal(**{**b["epoch"], "tsa_token": None}).epoch_hash(),
    )

    # 正向基线：自家根验自家 token 必须过。没有这条，下面的「必须失败」
    # 可能只是因为链校验根本没在跑。
    tok, ehash = tokens["freetsa"]
    assert verify_token(tok, ehash, roots["freetsa"]).ok is True

    # 反向：拿 FreeTSA 的根验 DigiCert / Sectigo 的 token
    for name, (tok, ehash) in tokens.items():
        if name == "freetsa":
            continue
        r = verify_token(tok, ehash, roots["freetsa"])
        assert r.ok is False, f"用 freetsa 的根验 {name} 的 token 竟然通过了"
        assert r.checks.get("证书链至可信根") is False, \
            f"{name}：链校验没有给出 False（可能压根没跑）"


def test_regression_cross_tsa_token_swap_must_fail(bundle, ca_pem):
    """把披露包里的 FreeTSA token 换成 DigiCert 的 token。

    签名是真的、证书链在自己那边也是真的，但它盖的是另一个 epoch_hash，
    而且根对不上。两道关卡都必须拦住。
    """
    other = next(iter(RSA_TOKENS.values()))
    bundle["tsa_token"] = other["tsa_token"]
    r = verify_bundle(bundle, ca_pem)
    assert r.ok is False
    assert r.checks["时间戳/messageImprint 匹配 epoch_hash"] is False


# ===========================================================================
# 回归 3：签名证书的有效期必须按 genTime 校验
# ===========================================================================

def test_regression_leaf_cert_validity_checked_at_gentime(bundle, ca_pem):
    """曾经：_chain_ok 只查各级签发者的有效期，不查叶子证书自己的。

    后果是 genTime 落在签名证书签发之前、或过期之后，照样判通过。
    而「签名时刻证书是否有效」正是 RFC 3161 §2.4.1 对 TSA 的核心要求，
    也正是时间戳的全部意义——一个在证书有效期之外产生的时间戳，
    证明不了任何事。

    实测过：在 FreeTSA 的证书上，过期后一天 → True，签发前一天 → True。
    """
    from asn1crypto import cms

    sd = cms.ContentInfo.load(base64.b64decode(bundle["tsa_token"]))["content"]
    certs = [c.chosen for c in sd["certificates"]]
    anchors = _load_anchors(ca_pem)
    leaf = certs[0]
    v = leaf["tbs_certificate"]["validity"]
    nb, na = v["not_before"].native, v["not_after"].native

    day = dt.timedelta(days=1)
    assert _chain_ok(leaf, certs, anchors, nb + day) is True, "有效期内应当通过"
    assert _chain_ok(leaf, certs, anchors, na - day) is True, "有效期内应当通过"
    assert _chain_ok(leaf, certs, anchors, nb - day) is False, "签发前应当失败"
    assert _chain_ok(leaf, certs, anchors, na + day) is False, "过期后应当失败"


def test_regression_leaf_validity_boundaries_are_inclusive(bundle, ca_pem):
    """边界值：not_before 与 not_after 那一刻本身算有效（RFC 5280）。"""
    from asn1crypto import cms

    sd = cms.ContentInfo.load(base64.b64decode(bundle["tsa_token"]))["content"]
    certs = [c.chosen for c in sd["certificates"]]
    anchors = _load_anchors(ca_pem)
    leaf = certs[0]
    v = leaf["tbs_certificate"]["validity"]
    sec = dt.timedelta(seconds=1)

    assert _chain_ok(leaf, certs, anchors, v["not_before"].native) is True
    assert _chain_ok(leaf, certs, anchors, v["not_after"].native) is True
    assert _chain_ok(leaf, certs, anchors, v["not_before"].native - sec) is False
    assert _chain_ok(leaf, certs, anchors, v["not_after"].native + sec) is False


def test_regression_issuer_validity_still_checked(bundle, ca_pem):
    """修叶子的有效期时不能把签发者那条丢了。

    构造：把 at_time 挪到 CA 有效期之外。此时叶子也必然在有效期外
    （叶子的窗口被 CA 包着），所以这条主要是防止有人在重构时
    把 _valid_at(issuer) 那一行删掉——用 CA 的边界做锚点。
    """
    from asn1crypto import cms

    sd = cms.ContentInfo.load(base64.b64decode(bundle["tsa_token"]))["content"]
    certs = [c.chosen for c in sd["certificates"]]
    anchors = _load_anchors(ca_pem)
    ca_validity = anchors[0]["tbs_certificate"]["validity"]

    beyond_ca = ca_validity["not_after"].native + dt.timedelta(days=1)
    assert _chain_ok(certs[0], certs, anchors, beyond_ca) is False


def test_regression_all_three_together_on_the_shipped_fixture(bundle, ca_pem):
    """三个缺陷都修好之后，出厂 fixture 必须仍然是九项全绿。

    回归测试容易只盯着「坏的要失败」，把「好的还要能过」丢掉。
    修得过头和修得不够，在这个库里同样是事故。
    """
    r = verify_bundle(bundle, ca_pem)
    assert r.ok is True, f"{r.checks} {r.missing} {r.errors}"
    assert set(r.checks) == set(BUNDLE_REQUIRED_CHECKS)
    assert r.missing == []
    assert r.errors == []
