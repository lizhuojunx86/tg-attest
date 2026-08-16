"""可信列表验签。需要 [eutl] 额外依赖（lxml + cryptography）。

这些测试用合成密钥现签一份文档，因此完全离线、不过期，而且能构造出
真实列表里不方便复现的负例（篡改、变换链被替换、签名者不在信任集合内）。

最重要的一条是 test_the_enveloped_transform_must_not_eat_the_tail：
那个 bug 在真实数据上只会让一部分成员国验不过，看上去像对方的问题。
"""

from __future__ import annotations

import base64
import hashlib

import pytest

lxml = pytest.importorskip("lxml", reason="需要 [eutl] 额外依赖")
pytest.importorskip("cryptography")

from lxml import etree  # noqa: E402

from tg_attest.eutl_build import (  # noqa: E402
    LOTL_SIGNING_CERT_SHA256,
    verify_tsl_signature,
)

DS = "http://www.w3.org/2000/09/xmldsig#"
ENVELOPED = f"{DS}enveloped-signature"
EXC = "http://www.w3.org/2001/10/xml-exc-c14n#"


def _keypair():
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test TL Signer")])
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(dt.datetime(2020, 1, 1))
            .not_valid_after(dt.datetime(2040, 1, 1))
            .sign(key, hashes.SHA256()))
    der = cert.public_bytes(serialization.Encoding.DER)
    return key, der


def _c14n(el):
    return etree.tostring(el, method="c14n", exclusive=True, with_comments=False)


def _sign(body_xml: bytes, key, cert_der: bytes, *, sig_tail: str = "",
          transforms=(ENVELOPED, EXC)) -> bytes:
    """给一份文档加一个 enveloped XMLDSig 签名，返回完整字节。

    sig_tail 控制 Signature 元素后面那段文本节点——荷兰的真实列表把换行
    放在那里，德国放在前一个兄弟节点上，这个参数就是用来复现那个差异的。
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    root = etree.fromstring(body_xml)

    sig = etree.SubElement(root, f"{{{DS}}}Signature")
    sig.text = "\n"
    sig.tail = sig_tail
    si = etree.SubElement(sig, f"{{{DS}}}SignedInfo")
    etree.SubElement(si, f"{{{DS}}}CanonicalizationMethod", Algorithm=EXC)
    etree.SubElement(si, f"{{{DS}}}SignatureMethod",
                     Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
    ref = etree.SubElement(si, f"{{{DS}}}Reference", URI="")
    ts = etree.SubElement(ref, f"{{{DS}}}Transforms")
    for t in transforms:
        etree.SubElement(ts, f"{{{DS}}}Transform", Algorithm=t)
    etree.SubElement(ref, f"{{{DS}}}DigestMethod",
                     Algorithm="http://www.w3.org/2001/04/xmlenc#sha256")
    dv = etree.SubElement(ref, f"{{{DS}}}DigestValue")
    sv = etree.SubElement(sig, f"{{{DS}}}SignatureValue")
    ki = etree.SubElement(sig, f"{{{DS}}}KeyInfo")
    x5d = etree.SubElement(ki, f"{{{DS}}}X509Data")
    etree.SubElement(x5d, f"{{{DS}}}X509Certificate").text = \
        base64.b64encode(cert_der).decode()

    # 文档摘要：按 enveloped 变换的语义，移除 Signature 但保留它的 tail。
    tmp = etree.fromstring(etree.tostring(root))
    s2 = tmp.findall(f"{{{DS}}}Signature")[0]
    tail, prev = s2.tail, s2.getprevious()
    tmp.remove(s2)
    if tail:
        if prev is not None:
            prev.tail = (prev.tail or "") + tail
        else:
            tmp.text = (tmp.text or "") + tail
    dv.text = base64.b64encode(hashlib.sha256(_c14n(tmp)).digest()).decode()

    sv.text = base64.b64encode(
        key.sign(_c14n(si), padding.PKCS1v15(), hashes.SHA256())).decode()
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8")


BODY = b'<?xml version="1.0" encoding="UTF-8"?>\n<TL xmlns="urn:t"><A>x</A>\n</TL>'


@pytest.fixture(scope="module")
def signer():
    key, der = _keypair()
    return key, der, frozenset({hashlib.sha256(der).hexdigest()})


def test_a_correctly_signed_list_verifies(signer):
    key, der, trusted = signer
    assert verify_tsl_signature(_sign(BODY, key, der), trusted).ok


def test_the_enveloped_transform_must_not_eat_the_tail(signer):
    """回归：Signature 后面的文本节点属于被签名内容，不能随元素一起删掉。

    lxml 的 remove() 会连 tail 一起删。签名者把换行放在 Signature.tail 上
    时（荷兰的真实列表就是这样），摘要就少了一个换行、验不过；放在前一个
    兄弟节点 tail 上时（德国、奥地利）删不删都一样。也就是说漏掉这个处理
    会让一部分成员国静默失败，而症状看起来像对方列表有问题。
    """
    key, der, trusted = signer
    for tail in ("", "\n", "\n  \n\t"):
        r = verify_tsl_signature(_sign(BODY, key, der, sig_tail=tail), trusted)
        assert r.ok, f"Signature.tail={tail!r} 时验签失败：{r.detail}"


def test_a_tampered_document_is_rejected(signer):
    key, der, trusted = signer
    xml = _sign(BODY, key, der)
    tampered = xml.replace(b"<A>x</A>", b"<A>y</A>")
    r = verify_tsl_signature(tampered, trusted)
    assert not r.ok
    assert "摘要" in r.detail


def test_a_signer_outside_the_trusted_set_is_rejected(signer):
    """不变量 4：信任根不得来自数据本身。

    签名在数学上有效，但签名者不在给定的可信集合内 —— 必须拒绝。
    否则任何人自签一份 XML 都能冒充成员国可信列表。
    """
    key, der, _ = signer
    other_key, other_der = _keypair()
    r = verify_tsl_signature(_sign(BODY, key, der),
                             frozenset({hashlib.sha256(other_der).hexdigest()}))
    assert not r.ok
    assert "不在可信集合内" in r.detail


@pytest.mark.parametrize("transforms", [
    (ENVELOPED,),                                   # 少一个
    (ENVELOPED, EXC, EXC),                          # 多一个
    (EXC, ENVELOPED),                               # 顺序反了
    ("http://www.w3.org/TR/1999/REC-xpath-19991116", EXC),   # 注入 XPath
])
def test_transform_chains_outside_the_mandated_shape_are_rejected(signer, transforms):
    """CID (EU) 2025/2164 附件第 3 点：URI="" 的 Reference 必须恰好两个
    Transform，顺序为 enveloped-signature 然后 exc-c14n。

    这条不是形式主义。放任任意变换链，攻击者可以构造一个「只签了文档某个
    子集」的签名，摘要照样对得上，而被排除的那部分可以随便改。
    """
    key, der, trusted = signer
    r = verify_tsl_signature(_sign(BODY, key, der, transforms=transforms), trusted)
    assert not r.ok
    assert "变换链" in r.detail or "Transforms" in r.detail


def test_more_than_one_signature_is_rejected(signer):
    key, der, trusted = signer
    xml = _sign(BODY, key, der)
    root = etree.fromstring(xml)
    root.append(etree.fromstring(etree.tostring(root.findall(f"{{{DS}}}Signature")[0])))
    r = verify_tsl_signature(etree.tostring(root), trusted)
    assert not r.ok


def test_the_pinned_lotl_trust_root_matches_the_official_journal():
    """信任根是 6 个 SHA-256，钉在代码里，对应 OJ C/2026/1944。

    这条不联网。它盯的是「有人改了这个集合」——比如为了让某份列表
    验过而临时加一个摘要进去。信任根的每一次变化都必须是一次显式的、
    能对照官方公报核对的改动。
    """
    assert LOTL_SIGNING_CERT_SHA256 == frozenset({
        "c0641c4f7d56c431b1c924742db7fce9c1eef7d7fd212113a2768486b3abcdc5",
        "e0a620fbb6747362bb933ac44169d676a553444716cf5f31605f12a22b8396b1",
        "df7e29360c34b2b8d6d5f40325c1d4d12c9922cecd33b7407674a74b2b3ca1e5",
        "b63d416744e7098bf9ec2caa596a93bc2468e37f8284ba65ecc061711bcbaa18",
        "236103f03a8031ae8f47f9059bf8de38564cdbfebedde4a597d50f8980aa653b",
        "d2064fdd70f6982dcc516b86d9d5c56aea939417c624b2e478c0b29de54f8474",
    })


@pytest.mark.network
def test_the_live_lotl_verifies_against_the_pinned_trust_root():
    """联网：真实 LOTL 必须用钉死的那 6 张证书验得过。

    这条会在信任根轮换（pivot LOTL）时失败，那时失败正是我们要的信号 ——
    公报换了，代码里的常量得跟着换。
    """
    from tg_attest.eutl_build import LOTL_URL, fetch
    r = verify_tsl_signature(fetch(LOTL_URL, timeout=60), LOTL_SIGNING_CERT_SHA256)
    assert r.ok, r.detail
