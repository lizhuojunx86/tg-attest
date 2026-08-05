"""不变量：出错时流程必须变得更严，不能变得更松。

这个文件对应的是一次全量排查——把代码库里每一个 except、每一个
if/else 的默认分支、每一个 .get(key, default) 都过一遍，问同一个问题：
这条路径走通时，判定是往「拒绝」偏还是往「通过」偏？

排查结果见 docs/fail-open-audit.md。下面是其中被判定为 fail-open
并已改掉的那几处的钉子。
"""

from __future__ import annotations

import base64
import json

import pytest

from helpers import FIXTURES, make_ledger, rewrite
from tg_attest.anchor import PKI_STATUS, Anchor, _read_tlv, parse_tsr
from tg_attest.record import GENESIS, EpochSeal, Ledger, merkle_root
from tg_attest.verify import _verify_sig, export_bundle, verify_bundle

# ===========================================================================
# verify.py — 未知摘要算法不得默认按 SHA-256 处理
# ===========================================================================

def test_unknown_digest_algorithm_is_rejected_not_defaulted():
    """曾经是 _HASH.get(algo, hashes.SHA256)()。

    「我不认识这个算法」被悄悄变成「那就当 SHA-256 吧」。多数情况下
    验签会失败（结果安全），但那是靠运气——判定不该建立在
    「猜错了大概率会失败」上面。
    """
    assert _verify_sig(object(), b"sig", b"data", "md5") is False
    assert _verify_sig(object(), b"sig", b"data", "whirlpool") is False
    assert _verify_sig(object(), b"sig", b"data", "") is False


def test_unsupported_key_type_is_rejected():
    """非 RSA / EC 的公钥（如 Ed25519）判失败，不是判通过。"""
    assert _verify_sig(object(), b"sig", b"data", "sha256") is False


# ===========================================================================
# verify.py — sid 找不到对应证书时不得退回 certs[0]
# ===========================================================================

def test_signer_not_found_is_an_error_not_a_fallback(bundle, ca_pem):
    """曾经的兜底是 certs[0]：sid 指向的证书不在 token 里时，
    直接拿第一张证书去验签。那验的已经不是签名者声称的那件事了。

    构造：把 token 里的 SignerInfo.sid 序列号改掉，使其匹配不上任何证书。
    """
    from asn1crypto import cms

    raw = base64.b64decode(bundle["tsa_token"])
    ci = cms.ContentInfo.load(raw)
    sid = ci["content"]["signer_infos"][0]["sid"]
    if sid.name != "issuer_and_serial_number":
        pytest.skip("fixture 的 sid 不是 issuer_and_serial_number")

    sid.chosen["serial_number"] = 0xDEADBEEF
    bundle["tsa_token"] = base64.b64encode(ci.dump(force=True)).decode()

    r = verify_bundle(bundle, ca_pem)
    assert r.ok is False
    assert any("找不到" in e for e in r.errors), r.errors


# ===========================================================================
# anchor.py — DER 截断必须报错，不能安静地少给几个字节
# ===========================================================================

@pytest.mark.parametrize("buf", [
    b"",
    b"\x30",
    b"\x30\x05",                       # 声称 5 字节，实际 0
    b"\x30\x05ab",                     # 声称 5 字节，实际 2
    b"\x30\x82\x01",                   # 长长度字段本身越界
    b"\x30\x82\x10\x00ab",             # 声称 4096 字节，实际 2
])
def test_truncated_der_raises_instead_of_silently_shortening(buf):
    """原来用 buf[i:i+n] 取值：长度字段声称 500 字节而实际只剩 9 字节时，
    切片安静地返回那 9 字节，解析继续往下走——把一个格式错误
    变成了一份看起来能用的数据。"""
    with pytest.raises(ValueError):
        _read_tlv(buf, 0)


def test_indefinite_length_is_rejected():
    """DER 不允许不定长编码。接受它等于接受 BER，解析边界就没了。"""
    with pytest.raises(ValueError, match="不定长"):
        _read_tlv(b"\x30\x80\x00\x00", 0)


def test_trailing_garbage_after_token_is_rejected():
    """PKIStatusInfo 之后的字节被整段当作 token。不检查的话，
    任何尾随垃圾都会被存下来，直到几个月后审计才发现它不是 token。"""
    body = bytes.fromhex("3003020100") + b"\x30\x03ab" + b"TRAILING"
    resp = b"\x30" + bytes([len(body)]) + body
    with pytest.raises(ValueError, match="多余数据"):
        parse_tsr(resp)


def test_token_that_is_not_a_sequence_is_rejected():
    body = bytes.fromhex("3003020100") + b"\x04\x02ab"      # OCTET STRING
    resp = b"\x30" + bytes([len(body)]) + body
    with pytest.raises(ValueError, match="SEQUENCE"):
        parse_tsr(resp)


@pytest.mark.parametrize("code", [6, 7, 99, 255])
def test_unknown_pki_status_is_not_success(code):
    """认不出的状态码一律不算成功。"""
    body = bytes([0x30, 0x03, 0x02, 0x01, code])
    resp = b"\x30" + bytes([len(body)]) + body
    status, _ = parse_tsr(resp)
    assert status == f"unknown({code})"
    assert status not in ("granted", "grantedWithMods")
    assert code not in PKI_STATUS


# ===========================================================================
# anchor.py — 写入时校验的三态语义
# ===========================================================================

def _anchor(**kw) -> Anchor:
    base = dict(epoch_id=0, anchored_hash="ab" * 32, tsa_url="https://x/tsr",
                status="granted", submitted_at="2026-08-04T00:00:00+00:00",
                token_b64="Zg==")
    return Anchor(**{**base, **kw})


def test_write_time_verification_failure_makes_anchor_unusable():
    """verified_at_write=False 表示「查了，没对上」——响应被替换。
    这个 anchor 必须不可用。"""
    assert _anchor(verified_at_write=False).ok is False


def test_write_time_verification_skipped_does_not_block():
    """None 表示「没装 [tsa]，没查」。不阻断——否则零依赖环境下
    根本没法锚定。这是刻意接受的风险，靠字段显式记录下来。"""
    assert _anchor(verified_at_write=None).ok is True
    assert _anchor(verified_at_write=True).ok is True


def test_write_time_check_detects_wrong_imprint():
    """拿一个真 token 去对一个不相干的哈希，必须判失败。
    这正是明文 http 上的中间人替换会长的样子。"""
    from tg_attest.anchor import _verify_at_write

    tok = base64.b64decode(json.loads(
        (FIXTURES / "rsa_tsa_tokens.json").read_text())["digicert"]["tsa_token"])
    verified, err = _verify_at_write(tok, "ff" * 32, None)
    assert verified is False
    assert "不是我们提交的哈希" in err


def test_write_time_check_detects_nonce_mismatch():
    """nonce 回显对不上 = 响应被替换或重放。"""
    from tg_attest.anchor import _verify_at_write

    data = json.loads((FIXTURES / "rsa_tsa_tokens.json").read_text())["digicert"]
    tok = base64.b64decode(data["tsa_token"])
    verified, err = _verify_at_write(tok, data["epoch_hash"], 0xDEADBEEF)
    assert verified is False
    assert "nonce" in err


def test_nonce_is_random_not_derived_from_the_digest():
    """曾经是 sha256(digest + b"nonce")[:8]，任何知道 digest 的人
    都能算出 nonce，防重放能力为零。现在必须是随机的。"""
    import inspect

    from tg_attest import anchor as anchor_mod

    src = inspect.getsource(anchor_mod.anchor_hash)
    assert "secrets.randbits" in src
    assert "hashlib.sha256" not in src


# ===========================================================================
# verify.py — 未锚定的包不得静默导出
# ===========================================================================

def test_exporting_an_unanchored_bundle_raises(tmp_path):
    """没有 tsa_token 的包在 verify_bundle 那边永远验不过，
    但导出时不说，使用者会以为手里有一份证据。"""
    led = make_ledger()
    led.seal_epoch()
    with pytest.raises(ValueError, match="没有时间戳 token"):
        export_bundle(led, 0, str(tmp_path / "b.json"))


def test_exporting_unanchored_is_possible_but_explicit(tmp_path):
    led = make_ledger()
    led.seal_epoch()
    p = tmp_path / "b.json"
    export_bundle(led, 0, str(p), allow_unanchored=True)
    b = json.loads(p.read_text(encoding="utf-8"))
    assert b["tsa_token"] is None
    assert "未锚定" in b["_verify"]["warning"]
    # 而且它确实验不过
    assert verify_bundle(b, (FIXTURES / "freetsa_ca.pem").read_bytes()).ok is False


def test_export_does_not_coerce_unserializable_values(tmp_path):
    """曾经是 json.dump(..., default=str)。序列化不了的值被悄悄转成
    字符串，包里的内容就和当初被哈希的内容对不上了，而症状是几个月后
    审计时一句「记录内容哈希自洽 = False」。现在当场抛错。"""
    led = make_ledger()
    seal = led.seal_epoch()
    led._epochs[0] = EpochSeal(**{**seal.__dict__, "tsa_token": "Zg=="})
    led._records[0] = rewrite(led._records[0], labels={"bad": {1, 2}})  # set 不可序列化
    with pytest.raises(TypeError):
        export_bundle(led, 0, str(tmp_path / "b.json"))


# ===========================================================================
# record.py — epoch 覆盖必须连续
# ===========================================================================

def test_gap_between_epochs_is_detected():
    """缝隙里的记录没有被任何 Merkle 根覆盖，也就没有被任何时间戳锚定，
    可以被连着 record_hash 一起重建而查不出来。"""
    led = make_ledger()
    for i in range(3):
        led.append(actor={"type": "agent", "id": "x"},
                   model={"provider": "p", "id": "m", "version": "1",
                          "params_hash": "h"},
                   inputs={"i": i}, output={"o": i},
                   decided_at=f"2026-06-{i + 1:02d}T00:00:00.000+00:00")
    seal = led.seal_epoch()
    assert led.verify() == []

    # 把 epoch 的起点往后挪，前面三条就落在缝里了
    led._epochs[0] = EpochSeal(**{**seal.__dict__, "start_seq": 3,
                                  "merkle_root": merkle_root(
                                      [r.record_hash for r in led._records[3:]])})
    assert any("覆盖区间不连续" in p for p in led.verify())


def test_epoch_covering_nonexistent_records_is_detected():
    led = make_ledger()
    seal = led.seal_epoch()
    led._epochs[0] = EpochSeal(**{**seal.__dict__, "end_seq": 99})
    assert any("不存在的记录" in p for p in led.verify())


def test_inverted_epoch_range_is_detected():
    led = make_ledger()
    seal = led.seal_epoch()
    led._epochs[0] = EpochSeal(**{**seal.__dict__, "start_seq": 2, "end_seq": 0})
    problems = led.verify()
    assert any("区间为空或倒置" in p or "覆盖区间不连续" in p for p in problems)


def test_unsealed_count_reports_the_exposure_window():
    """未封存的记录只受前向链保护，而前向链挡不住整段重建。
    这个数字就是当前的暴露窗口，生产环境该监控它。"""
    led = make_ledger()
    assert led.unsealed_count() == 3
    led.seal_epoch()
    assert led.unsealed_count() == 0
    led.append(actor={"type": "agent", "id": "x"},
               model={"provider": "p", "id": "m", "version": "1", "params_hash": "h"},
               inputs={"q": 1}, output={"a": 2},
               decided_at="2026-06-01T00:00:00.000+00:00")
    assert led.unsealed_count() == 1


# ===========================================================================
# record.py — verify_disclosure 的结构性 True 不等于证据
# ===========================================================================

def test_verify_disclosure_returns_false_on_malformed_input():
    """结构不对就是没通过。让异常穿出去的话，调用方写
    `if verify_disclosure(b):` 会直接崩，而不是走到 else 分支。"""
    for bad in [{}, {"record": {}}, {"record": {}, "record_hash": "x"},
                {"record": {}, "record_hash": "x", "proof": "nope"},
                {"record": {}, "record_hash": "x", "proof": [], "epoch": {}}]:
        assert Ledger.verify_disclosure(bad) is False


def test_verify_disclosure_does_not_prove_anchoring():
    """一个完全自造的账本能让 verify_disclosure 返回 True。
    它证明的只是「这条记录属于这个 Merkle 根」，不问那个根是谁算的。
    这就是为什么举证必须走 verify_bundle。"""
    led = make_ledger()
    led.seal_epoch()
    b = led.disclose(0)
    assert Ledger.verify_disclosure(b) is True          # 结构上成立
    b["tsa_token"] = None
    assert verify_bundle(b, None).ok is False           # 但不构成证据


def test_merkle_root_of_empty_span_is_genesis_not_a_valid_root():
    """空区间返回 GENESIS 常量。它是个哨兵值，不该被当成一个真实的根——
    seal_epoch 拒绝封存空区间，verify 拒绝倒置区间，两头堵住。"""
    assert merkle_root([]) == GENESIS
    led = make_ledger()
    led.seal_epoch()
    with pytest.raises(ValueError, match="没有新记录"):
        led.seal_epoch()
