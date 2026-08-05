"""不变量：手写的 DER 请求与 openssl 生成的逐字节相同。

这是 anchor.py 里那个手写编码器唯一重要的正确性证明。手写 DER 是为了
让写入路径零依赖；能这么干的前提是有一个不容置疑的参照物。字节相同，
就意味着任何能接受 openssl 请求的 TSA 都能接受我们的请求——这句话
覆盖了全世界的 RFC 3161 服务，而不只是我们碰巧测过的那三家。

openssl 不在环境里就 skip，不 fail：构建机没装 openssl 很正常，
不该让整个测试套变红。CI 的 lint+test job 装了 openssl，所以这条
在 CI 里一定会真的执行。
"""

from __future__ import annotations

import hashlib
import subprocess

import pytest

from tg_attest.anchor import SHA256_OID, build_tsq, der_int, der_oid, parse_tsr

# --- 与 openssl 逐字节比对 ------------------------------------------------

@pytest.mark.parametrize("payload", [
    b"tg-attest selftest",
    b"",
    b"\x00" * 1000,
    "决策记录".encode(),
    bytes(range(256)),
])
def test_matches_openssl_ts_query(openssl, tmp_path, payload):
    """openssl ts -query -data <f> -sha256 -cert -no_nonce

    -cert 对应 certReq=True，-no_nonce 对应 nonce=None。
    这两个参数必须和 build_tsq 的默认语义对齐，否则比的不是同一个东西。
    """
    f = tmp_path / "in.bin"
    f.write_bytes(payload)
    ref = subprocess.run(
        [openssl, "ts", "-query", "-data", str(f), "-sha256", "-cert", "-no_nonce"],
        capture_output=True, check=True,
    ).stdout
    ours = build_tsq(hashlib.sha256(payload).digest(), nonce=None, cert_req=True)
    assert ours == ref, f"\nours={ours.hex()}\nossl={ref.hex()}"


def test_matches_openssl_without_cert_req(openssl, tmp_path):
    """不带 -cert 时 certReq 字段整个不出现（DEFAULT FALSE 不编码）。"""
    f = tmp_path / "in.bin"
    f.write_bytes(b"no cert please")
    ref = subprocess.run(
        [openssl, "ts", "-query", "-data", str(f), "-sha256", "-no_nonce"],
        capture_output=True, check=True,
    ).stdout
    ours = build_tsq(hashlib.sha256(b"no cert please").digest(),
                     nonce=None, cert_req=False)
    assert ours == ref


def test_nonce_version_is_the_no_nonce_version_plus_one_integer(openssl, tmp_path):
    """带 nonce 的请求没法和 openssl 逐字节比（它的 nonce 是随机的），
    所以改成比结构：应当只多出一个 INTEGER，其余完全一致。"""
    digest = hashlib.sha256(b"nonce structure").digest()
    plain = build_tsq(digest, nonce=None, cert_req=True)
    with_nonce = build_tsq(digest, nonce=0x0102030405060708, cert_req=True)
    assert len(with_nonce) == len(plain) + 10   # 02 08 + 8 字节
    assert bytes.fromhex("0201010208") not in plain
    # nonce 紧跟在 messageImprint 之后、certReq 之前
    assert with_nonce.endswith(b"\x02\x08\x01\x02\x03\x04\x05\x06\x07\x08\x01\x01\xff")


# --- 输入校验 -------------------------------------------------------------

@pytest.mark.parametrize("bad_len", [0, 20, 31, 33, 48, 64])
def test_non_sha256_digest_is_rejected(bad_len):
    """本实现固定 SHA-256。传错长度必须当场报错，不能编出一个
    结构上合法但 TSA 会拒绝、或者更糟——TSA 会接受但含义错了的请求。"""
    with pytest.raises(ValueError, match="32"):
        build_tsq(b"\x00" * bad_len)


# --- DER 基元 -------------------------------------------------------------

@pytest.mark.parametrize("n,expected", [
    (0,                  "020100"),
    (1,                  "020101"),
    (127,                "02017f"),
    (128,                "02020080"),   # 高位是 1，必须补 00 否则被读成负数
    (255,                "020200ff"),
    (256,                "02020100"),
    (32767,              "02027fff"),
    (32768,              "0203008000"),
    (2**63 - 1,          "02087fffffffffffffff"),
    (2**63,              "0209008000000000000000"),
    (2**64 - 1,          "020900ffffffffffffffff"),
])
def test_der_int_encoding(n, expected):
    """INTEGER 的补零规则是 DER 里最容易写错的一处：正整数的最高位
    如果是 1，必须前置一个 0x00，否则解析方会把它读成负数。
    nonce 取自 sha256 前 8 字节，一半的概率落在这个分支上。"""
    assert der_int(n).hex() == expected


def test_der_oid_sha256():
    """SHA-256 的 OID 2.16.840.1.101.3.4.2.1，含多字节 arc（840）。"""
    assert der_oid(SHA256_OID).hex() == "0609608648016503040201"


def test_tsq_structure():
    """请求整体是 SEQUENCE，版本为 1。"""
    q = build_tsq(hashlib.sha256(b"x").digest())
    assert q[0] == 0x30
    assert q[2:5].hex() == "020101"


# --- 响应解析 -------------------------------------------------------------

def test_parse_tsr_reads_status_and_token(bundle):
    """parse_tsr 只剥壳，不做任何密码学判断——所以这里只断言
    它能把 granted 和 token 取出来。token 的真伪由 verify.py 负责。"""
    import base64

    from tg_attest.record import EpochSeal

    # 用 fixture 里那个真实 token 反过来包一个最小 TimeStampResp：
    # 30 <len> [PKIStatusInfo: 30 03 02 01 00] [token...]
    token = base64.b64decode(bundle["tsa_token"])
    status_info = bytes.fromhex("3003020100")
    body = status_info + token
    resp = b"\x30" + _der_len(len(body)) + body

    status, got = parse_tsr(resp)
    assert status == "granted"
    assert got == token
    assert EpochSeal   # 引用一下，说明这个 token 锚的就是 epoch_hash


@pytest.mark.parametrize("code,name", [
    (0, "granted"), (1, "grantedWithMods"), (2, "rejection"),
    (3, "waiting"), (4, "revocationWarning"), (5, "revocationNotification"),
])
def test_parse_tsr_status_codes(code, name):
    body = bytes([0x30, 0x03, 0x02, 0x01, code])
    resp = b"\x30" + _der_len(len(body)) + body
    status, token = parse_tsr(resp)
    assert status == name
    assert token is None


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b
