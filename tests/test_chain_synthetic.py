"""证书链校验里那些真 token 碰不到的分支。

这一整个文件是变异测试的产物。跑 mutmut 之前，_chain_ok 的测试看起来
是够的——正向能过、换个根会失败、有效期边界也测了。变异测试指出其中
四个分支从来没被执行过，而且它们全都朝放行的方向：

    _chain_ok  `if not _valid_at(issuer): return False`  → 改成 return True 仍全绿
    _chain_ok  `if not _verify_sig(issuer, cur): return False` → 改成 return True 仍全绿
    _chain_ok  循环耗尽后的 `return False`          → 改成 return True 仍全绿
    _eku_status `extn_id == EKU and critical`       → 改成 or 仍全绿

第二条最严重：它的含义是「这张证书的签名根本验不过，但链算通过」。
一个伪造的中间 CA 就能走通。它没被测到的原因很具体——已有的
「换个不相干的根」用例走的是更早的分支（pool 里找不到签发者就返回了），
压根到不了验签那一步。

真实 TSA 不会签一张 EKU 非 critical 的证书，也没法让 FreeTSA 的根
在它自己叶子证书的有效期内过期，所以这些只能用合成证书测。见 synthpki.py。
"""

from __future__ import annotations

import datetime as dt

import pytest
from cryptography.x509.oid import ExtendedKeyUsageOID

from synthpki import EPOCH, make_cert, make_key, simple_chain, to_asn1
from tg_attest.verify import EKU_TIMESTAMPING, _chain_ok, _eku_status, _load_anchors

DAY = dt.timedelta(days=1)


# --- 基线：正常链必须通过 -------------------------------------------------

def test_valid_synthetic_chain_passes():
    """没有这条，下面所有「必须失败」都可能只是因为合成证书本身有问题。"""
    root, leaf, _, _ = simple_chain()
    assert _chain_ok(leaf, [leaf, root], [root], EPOCH) is True


# --- 签发者签名验不过 → 必须失败 -----------------------------------------

def test_forged_issuer_with_matching_subject_is_rejected():
    """伪造的中间 CA：主体名和真 CA 一模一样，但密钥是自己的。

    _chain_ok 用 subject 做 pool 的键来找签发者，所以这张伪造证书
    **能被找到**，有效期也正常——唯一挡住它的就是验签那一步。
    这正是变异测试指出的、之前完全没被覆盖的那条分支。
    """
    real_root_key, leaf_key, evil_key = make_key(), make_key(), make_key()
    real_root = make_cert("synth-root", real_root_key, ca=True, eku=None)
    leaf = make_cert("synth-tsa", leaf_key, issuer_cn="synth-root",
                     issuer_key=real_root_key)
    # 同名不同钥。leaf 并不是它签的。
    evil_root = make_cert("synth-root", evil_key, ca=True, eku=None)

    leaf_a, evil_a = to_asn1(leaf), to_asn1(evil_root)
    assert _chain_ok(leaf_a, [leaf_a, evil_a], [evil_a], EPOCH) is False, \
        "签名验不过的签发者竟然让链通过了"

    # 对照组：换成真根就该通过，证明失败原因确实是签名而不是别的
    real_a = to_asn1(real_root)
    assert _chain_ok(leaf_a, [leaf_a, real_a], [real_a], EPOCH) is True


def test_leaf_tampered_after_signing_is_rejected():
    """改过内容的叶子证书，签名对不上。"""
    root, leaf, _, _ = simple_chain()
    raw = bytearray(leaf.dump())
    raw[-1] ^= 0xFF                      # 翻签名的最后一位
    from asn1crypto import x509 as a_x509
    try:
        bad = a_x509.Certificate.load(bytes(raw))
        assert _chain_ok(bad, [bad, root], [root], EPOCH) is False
    except ValueError:
        pass                             # 解析就失败也算拒绝


# --- 签发者在 genTime 时无效 → 必须失败 -----------------------------------

def test_issuer_expired_at_gentime_is_rejected():
    """签发者过期、但叶子仍在有效期内。

    用真证书造不出这个场景——FreeTSA 的根有效期完全包住它的叶子。
    而 _chain_ok 先查叶子再查签发者，所以叶子有效时才会走到签发者那条分支。
    """
    root_key, leaf_key = make_key(), make_key()
    # 根在 EPOCH 之前就过期了
    root = make_cert("synth-root", root_key, ca=True, eku=None,
                     not_before=EPOCH - 800 * DAY, not_after=EPOCH - 10 * DAY)
    # 叶子在 EPOCH 时有效
    leaf = make_cert("synth-tsa", leaf_key, issuer_cn="synth-root",
                     issuer_key=root_key,
                     not_before=EPOCH - DAY, not_after=EPOCH + 100 * DAY)

    root_a, leaf_a = to_asn1(root), to_asn1(leaf)
    from tg_attest.verify import _valid_at
    assert _valid_at(leaf_a, EPOCH) is True, "前提：叶子此刻必须是有效的"
    assert _valid_at(root_a, EPOCH) is False, "前提：签发者此刻必须已过期"

    assert _chain_ok(leaf_a, [leaf_a, root_a], [root_a], EPOCH) is False, \
        "签发者已过期，链却算通过"


def test_issuer_not_yet_valid_at_gentime_is_rejected():
    root_key, leaf_key = make_key(), make_key()
    root = make_cert("synth-root", root_key, ca=True, eku=None,
                     not_before=EPOCH + 10 * DAY, not_after=EPOCH + 800 * DAY)
    leaf = make_cert("synth-tsa", leaf_key, issuer_cn="synth-root",
                     issuer_key=root_key,
                     not_before=EPOCH - DAY, not_after=EPOCH + 100 * DAY)
    root_a, leaf_a = to_asn1(root), to_asn1(leaf)
    assert _chain_ok(leaf_a, [leaf_a, root_a], [root_a], EPOCH) is False


# --- 链深超限 → 必须失败 ---------------------------------------------------

def test_chain_deeper_than_the_limit_is_rejected():
    """超过 8 层就放弃并判失败。循环耗尽后那个 return False
    改成 return True 之前是全绿的——意味着「查不完就放行」。"""
    keys = [make_key() for _ in range(12)]
    certs, issuer_key, issuer_cn = [], None, None
    for i in range(12):
        c = make_cert(f"lvl-{i}", keys[i], issuer_cn=issuer_cn,
                      issuer_key=issuer_key, ca=True, eku=None)
        certs.append(c)
        issuer_key, issuer_cn = keys[i], f"lvl-{i}"

    leaf = make_cert("deep-tsa", make_key(), issuer_cn="lvl-11",
                     issuer_key=keys[11])
    chain = [to_asn1(c) for c in certs]
    root_a = chain[0]                       # 自签根，在 12 层之外
    leaf_a = to_asn1(leaf)

    assert _chain_ok(leaf_a, [leaf_a, *chain], [root_a], EPOCH) is False, \
        "链深超限时应当判失败，不是判通过"


def test_cyclic_chain_terminates_and_is_rejected():
    """两张证书互相签发：pool 会在它们之间来回跳。
    seen 集合负责断开，断不开就是死循环。"""
    ka, kb = make_key(), make_key()
    a = make_cert("cyc-a", ka, issuer_cn="cyc-b", issuer_key=kb, ca=True, eku=None)
    b = make_cert("cyc-b", kb, issuer_cn="cyc-a", issuer_key=ka, ca=True, eku=None)
    leaf = make_cert("cyc-tsa", make_key(), issuer_cn="cyc-a", issuer_key=ka)

    a_, b_, leaf_ = to_asn1(a), to_asn1(b), to_asn1(leaf)
    unrelated_root = to_asn1(make_cert("elsewhere", make_key(), ca=True, eku=None))
    assert _chain_ok(leaf_, [leaf_, a_, b_], [unrelated_root], EPOCH) is False


# --- 叶子本身就是信任根 ----------------------------------------------------

def test_leaf_that_is_itself_a_trust_anchor_passes():
    """直接信任这张证书。这条分支之前也没被覆盖过。"""
    key = make_key()
    self_signed = make_cert("self-tsa", key, ca=True)
    c = to_asn1(self_signed)
    assert _chain_ok(c, [c], [c], EPOCH) is True


def test_unknown_issuer_is_rejected():
    """签发者不在 pool 里 —— 这是已有测试覆盖到的那条早分支，
    留一条在这里做对照，说明它和上面几条走的不是同一条路。"""
    root, leaf, _, _ = simple_chain()
    other = to_asn1(make_cert("elsewhere", make_key(), ca=True, eku=None))
    assert _chain_ok(leaf, [leaf], [other], EPOCH) is False


# --- EKU ------------------------------------------------------------------

def test_eku_must_be_critical():
    """RFC 3161 §2.3 要求 timeStamping EKU 扩展为 critical。

    把 `extn_id == EKU 且 critical` 改成 `或` 之后整套测试仍然全绿——
    因为 or 会让任何一张带 critical 扩展（比如 basicConstraints）的证书
    都算「EKU 是 critical 的」。真实 TSA 证书都合规，所以测不出来。
    """
    _, leaf_ok, _, _ = simple_chain(leaf_eku_critical=True)
    only_ts, crit = _eku_status(leaf_ok)
    assert (only_ts, crit) == (True, True)

    _, leaf_bad, _, _ = simple_chain(leaf_eku_critical=False)
    only_ts, crit = _eku_status(leaf_bad)
    assert only_ts is True
    assert crit is False, "EKU 不是 critical，却被判成 critical"


def test_eku_must_contain_only_timestamping():
    """一张同时能做 TLS 服务端的证书不该被当成 TSA 证书用。"""
    _, leaf, _, _ = simple_chain(
        leaf_eku=(ExtendedKeyUsageOID.TIME_STAMPING, ExtendedKeyUsageOID.SERVER_AUTH))
    only_ts, _ = _eku_status(leaf)
    assert only_ts is False


def test_certificate_without_eku_is_not_a_tsa_cert():
    """完全没有 EKU 扩展的证书（比如一张 CA 证书）不能冒充 TSA。"""
    ca = to_asn1(make_cert("plain-ca", make_key(), ca=True, eku=None))
    only_ts, crit = _eku_status(ca)
    assert only_ts is False
    assert crit is False


def test_eku_with_wrong_single_usage_is_rejected():
    _, leaf, _, _ = simple_chain(leaf_eku=(ExtendedKeyUsageOID.SERVER_AUTH,))
    only_ts, _ = _eku_status(leaf)
    assert only_ts is False


def test_timestamping_oid_constant_is_correct():
    """1.3.6.1.5.5.7.3.8 —— 写错这个常量，EKU 检查就永远是 False，
    表现为「所有 token 都验不过」，方向是安全的但一样是 bug。"""
    assert EKU_TIMESTAMPING == "1.3.6.1.5.5.7.3.8"
    assert ExtendedKeyUsageOID.TIME_STAMPING.dotted_string == EKU_TIMESTAMPING


# --- _load_anchors --------------------------------------------------------

def test_load_anchors_reads_every_certificate_in_a_multi_cert_pem():
    """多证书 PEM。之前只测过单证书的 fixture，于是解析循环里
    「处理完一张之后把状态复位」那一步坏掉也测不出来。"""
    from synthpki import to_pem

    certs = [make_cert(f"root-{i}", make_key(), ca=True, eku=None) for i in range(3)]
    pem = b"".join(to_pem(c) for c in certs)
    loaded = _load_anchors(pem)
    assert len(loaded) == 3
    assert {c.subject.native["common_name"] for c in loaded} == \
        {"root-0", "root-1", "root-2"}


def test_load_anchors_ignores_surrounding_noise():
    """PEM 文件里常有注释和空行。"""
    from synthpki import to_pem

    c = make_cert("noisy-root", make_key(), ca=True, eku=None)
    pem = b"# comment\n\n" + to_pem(c) + b"\ntrailing junk\n"
    assert len(_load_anchors(pem)) == 1


@pytest.mark.parametrize("blob", [b"", b"not a pem at all", b"-----BEGIN CERTIFICATE-----\n"])
def test_load_anchors_returns_empty_on_garbage(blob):
    assert _load_anchors(blob) == []


# --- 按 sid 定位签名证书 ---------------------------------------------------
# 三家默认 TSA 都用 issuer_and_serial_number，subject_key_identifier
# 那条分支拿真 token 一次也走不到——变异测试把那几行整个标成了存活。

def _sid_ias(cert):
    from asn1crypto import cms
    return cms.SignerIdentifier({
        "issuer_and_serial_number": cms.IssuerAndSerialNumber({
            "issuer": cert.issuer, "serial_number": cert.serial_number})})


def _sid_ski(key_id: bytes):
    from asn1crypto import cms
    return cms.SignerIdentifier({"subject_key_identifier": key_id})


def test_find_signer_by_issuer_and_serial():
    from tg_attest.verify import _find_signer
    root, leaf, _, _ = simple_chain()
    assert _find_signer([root, leaf], _sid_ias(leaf)) is leaf
    assert _find_signer([root, leaf], _sid_ias(root)) is root


def test_find_signer_requires_both_issuer_and_serial():
    """序列号只在单个签发者内唯一。原来只比 serial，两家 CA
    签出同号证书就会选错人。"""
    from tg_attest.verify import _find_signer

    ka, kb = make_key(), make_key()
    # 同一个序列号，不同签发者
    a = make_cert("same-serial", ka, issuer_cn="ca-a", issuer_key=ka, serial=4242)
    b = make_cert("same-serial", kb, issuer_cn="ca-b", issuer_key=kb, serial=4242)
    a_, b_ = to_asn1(a), to_asn1(b)

    assert _find_signer([a_, b_], _sid_ias(a_)) is a_
    assert _find_signer([b_, a_], _sid_ias(b_)) is b_


def test_find_signer_by_subject_key_identifier():
    from tg_attest.verify import _find_signer
    root, leaf, _, _ = simple_chain()
    if leaf.key_identifier is None:
        pytest.skip("合成证书没有 SKI 扩展")
    assert _find_signer([root, leaf], _sid_ski(leaf.key_identifier)) is leaf


def test_find_signer_returns_none_when_nothing_matches():
    """找不到就是 None，不能退回 certs[0]。"""
    from asn1crypto import cms

    from tg_attest.verify import _find_signer
    root, leaf, _, _ = simple_chain()
    bogus = cms.SignerIdentifier({
        "issuer_and_serial_number": cms.IssuerAndSerialNumber({
            "issuer": leaf.issuer, "serial_number": 0xDEADBEEF})})
    assert _find_signer([root, leaf], bogus) is None
    assert _find_signer([], _sid_ias(leaf)) is None
    assert _find_signer([root, leaf], _sid_ski(b"\x00" * 20)) is None
