"""合成 PKI：用来测那些真实 TSA 永远不会签给你的证书。

变异测试暴露的问题是，证书链校验里最要命的几个分支根本没有被覆盖：
签发者签名验不过、签发者在 genTime 时已过期、链深超限、EKU 不是 critical。
拿真 token 测不到这些——没有哪家 TSA 会签一张 EKU 非 critical 的证书，
也没法让 FreeTSA 的根在它自己叶子证书的有效期内过期。

所以这里自己造。造出来的东西只喂给 _chain_ok / _eku_status，
不冒充任何真实机构，也不进 fixtures。
"""

from __future__ import annotations

import datetime as dt

from asn1crypto import x509 as a_x509
from cryptography import x509 as c_x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

EPOCH = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)


def _name(cn: str) -> c_x509.Name:
    return c_x509.Name([c_x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_key():
    # 1024 位：合成证书只用于验签逻辑，不承载任何真实信任，够快就行。
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)


def make_cert(cn, key, *, issuer_cn=None, issuer_key=None,
              not_before=None, not_after=None,
              eku=(ExtendedKeyUsageOID.TIME_STAMPING,), eku_critical=True,
              ca=False, serial=None):
    """签一张证书。issuer_key 为 None 时自签。"""
    issuer_key = issuer_key or key
    builder = (
        c_x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(_name(issuer_cn or cn))
        .public_key(key.public_key())
        .serial_number(serial or c_x509.random_serial_number())
        .not_valid_before(not_before or EPOCH - dt.timedelta(days=365))
        .not_valid_after(not_after or EPOCH + dt.timedelta(days=365))
    )
    if ca:
        builder = builder.add_extension(
            c_x509.BasicConstraints(ca=True, path_length=None), critical=True)
    if eku:
        builder = builder.add_extension(
            c_x509.ExtendedKeyUsage(list(eku)), critical=eku_critical)
    # 带上 SKI，否则 SignerIdentifier 的 subject_key_identifier 分支
    # 在测试里也走不到——那正是变异测试标出来没被覆盖的地方之一。
    builder = builder.add_extension(
        c_x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    return builder.sign(issuer_key, hashes.SHA256())


def to_asn1(cert) -> a_x509.Certificate:
    """cryptography 的 Certificate → asn1crypto 的 Certificate。

    _chain_ok 和 _eku_status 吃的是 asn1crypto 对象。
    """
    return a_x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER))


def to_pem(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def simple_chain(*, leaf_eku_critical=True, leaf_eku=(ExtendedKeyUsageOID.TIME_STAMPING,)):
    """root(CA, 自签) → leaf(TSA)。返回 (root_asn1, leaf_asn1, root_pem, keys)。"""
    root_key, leaf_key = make_key(), make_key()
    root = make_cert("synth-root", root_key, ca=True, eku=None)
    leaf = make_cert("synth-tsa", leaf_key, issuer_cn="synth-root",
                     issuer_key=root_key, eku=leaf_eku, eku_critical=leaf_eku_critical)
    return to_asn1(root), to_asn1(leaf), to_pem(root), (root_key, leaf_key)
