"""不变量：signatureAlgorithm 没有绑定哈希时，摘要算法取自 digestAlgorithm。

RFC 5652 §5.3。三家默认 TSA 恰好分成两类：

    FreeTSA   sha512_ecdsa     哈希写在算法 OID 里
    DigiCert  rsassa_pkcs1v15  OID 里没有哈希，digestAlgorithm 是 sha256
    Sectigo   rsassa_pkcs1v15  OID 里没有哈希，digestAlgorithm 是 sha384

参考实现直接取 si["signature_algorithm"].hash_algo。对后两家，asn1crypto
会抛 ValueError: Hash algorithm not known for rsassa_pkcs1v15，
于是验签和证书链校验两步整个没跑——而 verify_bundle 当时只看 checks
不看 errors，结论是「通过」。三家 TSA 里有两家从来没被真正验过签。

这个 fixture 是真实的 DigiCert / Sectigo token，把这条钉在离线测试里。
"""

from __future__ import annotations

import base64
import json

import pytest

from helpers import FIXTURES
from tg_attest.verify import verify_token

TOKENS = json.loads((FIXTURES / "rsa_tsa_tokens.json").read_text(encoding="utf-8"))


@pytest.fixture(params=sorted(TOKENS), ids=sorted(TOKENS))
def rsa_token(request) -> dict:
    return TOKENS[request.param]


def test_fixture_covers_the_unbound_hash_case(rsa_token):
    """先确认 fixture 本身就是要测的那种情况，否则底下全是假绿。"""
    assert rsa_token["signature_algorithm"] == "rsassa_pkcs1v15"
    assert rsa_token["digest_algorithm"] in ("sha256", "sha384")


def test_signature_of_rsa_token_is_actually_verified(rsa_token):
    """签名这一步必须真的跑，而且必须通过。"""
    r = verify_token(base64.b64decode(rsa_token["tsa_token"]),
                     rsa_token["epoch_hash"], None)
    assert "TSA 签名有效" in r.checks, "验签这一步根本没跑到"
    assert r.checks["TSA 签名有效"] is True
    assert r.checks["messageImprint 匹配 epoch_hash"] is True
    # 没给 ca_bundle，所以整体仍然不通过，且 errors 里只该有信任根这一条
    assert r.ok is False
    assert [e for e in r.errors if "信任根" not in e] == []


def test_no_hash_algorithm_error_leaks_into_errors(rsa_token):
    """回归：errors 里不能再出现 'Hash algorithm not known'。"""
    r = verify_token(base64.b64decode(rsa_token["tsa_token"]),
                     rsa_token["epoch_hash"], None)
    assert not any("Hash algorithm not known" in e for e in r.errors), r.errors


def test_tampered_rsa_token_still_fails(rsa_token):
    """修好了兼容性，不能顺手把安全性也修没了：改一位仍须验不过。"""
    raw = bytearray(base64.b64decode(rsa_token["tsa_token"]))
    raw[-1] ^= 0xFF
    r = verify_token(bytes(raw), rsa_token["epoch_hash"], None)
    assert r.ok is False
    assert r.checks.get("TSA 签名有效") is not True


def test_rsa_token_for_wrong_hash_is_rejected(rsa_token):
    r = verify_token(base64.b64decode(rsa_token["tsa_token"]), "ab" * 32, None)
    assert r.ok is False
    assert r.checks["messageImprint 匹配 epoch_hash"] is False


def test_a_valid_token_against_an_unrelated_ca_is_not_a_pass(rsa_token, ca_pem):
    """这是那条 fail-open 最完整的复现：真 token、真签名，
    但拿 FreeTSA 的根去验 DigiCert 的证书链。必须是失败。"""
    r = verify_token(base64.b64decode(rsa_token["tsa_token"]),
                     rsa_token["epoch_hash"], ca_pem)
    assert r.ok is False
    assert r.checks["证书链至可信根"] is False
