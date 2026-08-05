"""不变量：披露包的验证是一条完整链条，任一环断则整体失败。

    record 内容 → record_hash
                → Merkle 包含证明 → merkle_root
                → epoch_hash（排除 tsa_token）
                → TSA token 内的 messageImprint
                → TSA 签名（signedAttrs + 证书链 + timeStamping EKU）
                → genTime

这里用的是 fixtures/decision_0000.json —— 真实跑出来的包，freetsa.org
签的时间戳。整套测试完全离线，而且不会过期：证书有效期是拿 token 内
被签名的 genTime 校验的，不是拿 datetime.now()。

本文件里有一半用例断言的是「必须失败」。对一个验证工具来说这半边更重要：
把好的判成坏的，用户会来提 issue；把坏的判成好的，没有人会发现。
"""

from __future__ import annotations

import base64
import json
import subprocess
import sys

import pytest

from tg_attest.record import EpochSeal, hash_obj
from tg_attest.verify import BUNDLE_REQUIRED_CHECKS, verify_bundle, verify_token

# 不写死数字：检查项清单是会长的（这一轮就加了完整性档案那条）。
# 断言「产出的检查项 == 必需清单」比断言「一共 9 项」更有意义，
# 而且加了新检查忘了注册时它会失败，写死数字只会逼人改数字。
TOTAL_CHECKS = len(BUNDLE_REQUIRED_CHECKS)


# --- 正向 -----------------------------------------------------------------

def test_fixture_bundle_verifies(bundle, ca_pem):
    r = verify_bundle(bundle, ca_pem)
    assert r.ok, f"{r.checks} {r.errors}"
    assert len(r.checks) == TOTAL_CHECKS
    assert all(v is True for v in r.checks.values())
    assert not r.errors
    assert r.gen_time and r.tsa_subject


def test_every_link_in_the_chain_is_actually_checked(bundle, ca_pem):
    """九项检查，逐条点名。少一项就是少一环，而链条的强度等于最弱一环。"""
    r = verify_bundle(bundle, ca_pem)
    for name in ["记录内容哈希自洽",
                 "记录满足所声明的完整性档案",
                 "Merkle 包含证明有效",
                 "时间戳/eContentType 为 id-ct-TSTInfo",
                 "时间戳/messageImprint 匹配 epoch_hash",
                 "时间戳/EKU 仅含 timeStamping",
                 "时间戳/EKU 扩展为 critical",
                 "时间戳/signedAttrs.message-digest 匹配内容",
                 "时间戳/TSA 签名有效",
                 "时间戳/证书链至可信根"]:
        assert r.checks.get(name) is True, f"缺少或未通过：{name}"


def test_bundle_carries_no_ca_certificate(bundle):
    """信任根不得来自披露包自身。包里自带 CA 的话，伪造者会连自己的根
    一起打进去，整个证明退化成同义反复。"""
    blob = json.dumps(bundle)
    assert "BEGIN CERTIFICATE" not in blob
    assert "ca_bundle" not in bundle and "ca" not in bundle
    assert bundle["_verify"]["note"]


def test_bundle_does_not_contain_other_records(bundle):
    """选择性披露：包里只有 seq=0，同 epoch 的其他记录内容与哈希都不出现。"""
    assert bundle["record"]["seq"] == 0
    assert isinstance(bundle["proof"], list) and bundle["proof"]
    # 证明路径里是兄弟节点哈希，不是别人的记录内容
    blob = json.dumps(bundle["proof"])
    assert "MSFT" not in blob and "NVDA" not in blob


def test_epoch_hash_in_bundle_matches_the_anchored_imprint(bundle):
    """把 token 单独拎出来、epoch.tsa_token 置 None，是为了避免自指。
    这里验证那个 None 化之后算出的 epoch_hash 正是 TSA 盖的那个。"""
    from asn1crypto import cms, tsp

    seal = EpochSeal(**{**bundle["epoch"], "tsa_token": None})
    sd = cms.ContentInfo.load(base64.b64decode(bundle["tsa_token"]))["content"]
    tst = tsp.TSTInfo.load(sd["encap_content_info"]["content"].contents)
    assert tst["message_imprint"]["hashed_message"].native.hex() == seal.epoch_hash()
    assert bundle["epoch"]["tsa_token"] is None


# --- 反向：没有信任根不给通过 ---------------------------------------------

def test_no_ca_bundle_is_not_a_pass(bundle):
    """「没有信任根也算通过」是最常见的误用。刻意拒绝。"""
    r = verify_bundle(bundle, None)
    assert r.ok is False
    assert any("信任根" in e for e in r.errors)


def test_wrong_ca_is_rejected(bundle, tmp_path):
    """拿一个不相干的自签根来验，证书链必须挂。"""
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "not-the-real-ca")])
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1)
            .not_valid_before(dt.datetime(2020, 1, 1))
            .not_valid_after(dt.datetime(2040, 1, 1))
            .sign(key, hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM)

    r = verify_bundle(bundle, pem)
    assert r.ok is False
    assert r.checks.get("时间戳/证书链至可信根") is False


# --- 反向：篡改包内容 -----------------------------------------------------

@pytest.mark.parametrize("path,value", [
    (("record", "output_hash"), "ab" * 32),
    (("record", "inputs_hash"), "cd" * 32),
    (("record", "decided_at"), "2020-01-01T00:00:00.000+00:00"),
    (("record", "seq"), 7),
    (("record", "prev_hash"), "ef" * 32),
])
def test_tampering_the_record_breaks_the_content_hash(bundle, ca_pem, path, value):
    bundle[path[0]][path[1]] = value
    r = verify_bundle(bundle, ca_pem)
    assert r.ok is False
    assert r.checks["记录内容哈希自洽"] is False


def test_tampering_the_evidence_as_of_is_caught(bundle, ca_pem):
    """as_of 是本库存在的理由。改它 = 伪造「决策时看到的是什么」。"""
    bundle["record"]["evidence"][0]["as_of"] = "2026-05-03T20:00:00+00:00"
    r = verify_bundle(bundle, ca_pem)
    assert r.ok is False
    assert r.checks["记录内容哈希自洽"] is False


def test_recomputing_record_hash_is_stopped_by_the_merkle_proof(bundle, ca_pem):
    """篡改者改内容后把 record_hash 一起重算——下一层挡住它。"""
    bundle["record"]["output_hash"] = "ab" * 32
    bundle["record_hash"] = hash_obj(bundle["record"])
    r = verify_bundle(bundle, ca_pem)
    assert r.ok is False
    assert r.checks["记录内容哈希自洽"] is True     # 这一层被绕过了
    assert r.checks["Merkle 包含证明有效"] is False  # 这一层没有


def test_forging_the_merkle_root_is_stopped_by_the_timestamp(bundle, ca_pem):
    """再往上一层：连 merkle_root 也改掉，让包含证明自洽。
    epoch_hash 随之改变，与 TSA 签的 messageImprint 对不上。
    篡改者要绕过这一层，需要让 TSA 重新签一个过去的时间。"""
    from tg_attest.record import _leaf, _node

    forged_rec = dict(bundle["record"], output_hash="ab" * 32)
    forged_hash = hash_obj(forged_rec)
    cur = _leaf(forged_hash)
    for side, sib in bundle["proof"]:
        cur = _node(sib, cur) if side == "L" else _node(cur, sib)

    bundle["record"] = forged_rec
    bundle["record_hash"] = forged_hash
    bundle["epoch"]["merkle_root"] = cur

    r = verify_bundle(bundle, ca_pem)
    assert r.ok is False
    assert r.checks["记录内容哈希自洽"] is True
    assert r.checks["Merkle 包含证明有效"] is True
    assert r.checks["时间戳/messageImprint 匹配 epoch_hash"] is False


@pytest.mark.parametrize("field", ["epoch_id", "start_seq", "end_seq",
                                   "prev_epoch_hash", "sealed_at"])
def test_tampering_any_epoch_field_breaks_the_imprint(bundle, ca_pem, field):
    bundle["epoch"][field] = 999 if isinstance(bundle["epoch"][field], int) else "x"
    r = verify_bundle(bundle, ca_pem)
    assert r.ok is False
    assert r.checks["时间戳/messageImprint 匹配 epoch_hash"] is False


def test_tampering_the_proof_is_caught(bundle, ca_pem):
    bundle["proof"][0][1] = "ab" * 32
    r = verify_bundle(bundle, ca_pem)
    assert r.ok is False
    assert r.checks["Merkle 包含证明有效"] is False


# --- 反向：token 层面 -----------------------------------------------------
# 下面三条是回归测试。它们对应参考实现里一个会静默放行的缺陷：
# verify_bundle 只看 checks 全为 True，不看 errors，也不看 checks 是否为空。
# 于是 token 解析一抛异常，就只剩下记录层那两项检查，all() 给出「通过」。
# 一个完全是垃圾的时间戳能验出 ok=True。

def test_garbage_token_is_not_a_pass(bundle, ca_pem):
    bundle["tsa_token"] = base64.b64encode(b"this is not a CMS structure").decode()
    r = verify_bundle(bundle, ca_pem)
    assert r.ok is False, "垃圾 token 被判为通过——验证工具在往放行方向失败"
    assert r.errors


def test_empty_token_is_not_a_pass(bundle, ca_pem):
    bundle["tsa_token"] = ""
    r = verify_bundle(bundle, ca_pem)
    assert r.ok is False
    assert any("无时间戳" in e for e in r.errors)


def test_missing_token_is_not_a_pass(bundle, ca_pem):
    del bundle["tsa_token"]
    r = verify_bundle(bundle, ca_pem)
    assert r.ok is False


def test_token_for_a_different_hash_is_rejected(bundle, ca_pem):
    """真 token、真签名，但盖的是别的哈希。"""
    r = verify_token(base64.b64decode(bundle["tsa_token"]), "ab" * 32, ca_pem)
    assert r.ok is False
    assert r.checks["messageImprint 匹配 epoch_hash"] is False


def test_truncated_token_is_not_a_pass(bundle, ca_pem):
    raw = base64.b64decode(bundle["tsa_token"])
    bundle["tsa_token"] = base64.b64encode(raw[:len(raw) // 2]).decode()
    r = verify_bundle(bundle, ca_pem)
    assert r.ok is False


def test_flipping_a_byte_in_the_signature_is_caught(bundle, ca_pem):
    """token 尾部通常落在签名里。翻一位，签名校验必须挂。"""
    raw = bytearray(base64.b64decode(bundle["tsa_token"]))
    raw[-1] ^= 0xFF
    bundle["tsa_token"] = base64.b64encode(bytes(raw)).decode()
    r = verify_bundle(bundle, ca_pem)
    assert r.ok is False


def test_empty_checks_never_counts_as_pass(ca_pem):
    """all([]) 是 True。零项检查不能等于通过。"""
    r = verify_token(b"", "ab" * 32, ca_pem)
    assert r.ok is False
    assert r.errors


# --- 证书有效期必须按 genTime 判 ------------------------------------------

def test_signer_cert_validity_is_checked_against_gentime(bundle, ca_pem):
    """RFC 3161 §2.4.1：TSA 的签名证书必须在 genTime 时刻有效。

    参考实现只查了各级签发者的有效期，没查叶子证书自己的。后果是
    genTime 落在签名证书签发之前、或过期之后，照样判通过——而
    「签名时刻证书是否有效」正是时间戳的全部意义所在。
    """
    import datetime as dt

    from asn1crypto import cms

    from tg_attest.verify import _chain_ok, _load_anchors

    sd = cms.ContentInfo.load(base64.b64decode(bundle["tsa_token"]))["content"]
    certs = [c.chosen for c in sd["certificates"]]
    anchors = _load_anchors(ca_pem)
    leaf = certs[0]
    v = leaf["tbs_certificate"]["validity"]
    nb, na = v["not_before"].native, v["not_after"].native

    assert _chain_ok(leaf, certs, anchors, nb + dt.timedelta(days=1)) is True
    assert _chain_ok(leaf, certs, anchors, na - dt.timedelta(days=1)) is True
    assert _chain_ok(leaf, certs, anchors, nb - dt.timedelta(days=1)) is False
    assert _chain_ok(leaf, certs, anchors, na + dt.timedelta(days=1)) is False


def test_verification_does_not_depend_on_wall_clock(bundle, ca_pem):
    """这个包的结论今天和 2040 年必须一样。

    断言的具体形式：验证时用的时刻是 token 内被签名的 genTime，
    而 genTime 落在签名证书有效期之内——所以无论墙钟走到哪一年，
    _chain_ok 拿到的 at_time 都是同一个冻结的值，结论不变。
    这既是 fixture 不会过期的原因，也是长期归档记录在证书过期之后
    仍然可验的原因（对照 docs/threat-model.md 里的「长期保存」一节）。
    """
    import datetime as dt

    from asn1crypto import cms

    r = verify_bundle(bundle, ca_pem)
    assert r.ok

    gen = dt.datetime.fromisoformat(r.gen_time)
    assert gen.tzinfo is not None and gen.utcoffset() == dt.timedelta(0)

    sd = cms.ContentInfo.load(base64.b64decode(bundle["tsa_token"]))["content"]
    leaf = [c.chosen for c in sd["certificates"]][0]
    v = leaf["tbs_certificate"]["validity"]
    assert v["not_before"].native <= gen <= v["not_after"].native


# --- CLI ------------------------------------------------------------------

def _cli(*args) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "tg_attest.cli", *args],
                          capture_output=True, text=True)


def test_cli_exit_zero_on_valid(tmp_path, bundle_json, ca_pem):
    p = tmp_path / "b.json"
    p.write_text(json.dumps(bundle_json), encoding="utf-8")
    ca = tmp_path / "ca.pem"
    ca.write_bytes(ca_pem)
    r = _cli(str(p), "--ca", str(ca))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "通过" in r.stdout


def test_cli_exit_one_without_ca(tmp_path, bundle_json):
    """不给 --ca 就拒绝给出「通过」。退出码可以直接用于 CI 抽检。"""
    p = tmp_path / "b.json"
    p.write_text(json.dumps(bundle_json), encoding="utf-8")
    r = _cli(str(p))
    assert r.returncode == 1


def test_cli_exit_one_on_tampered(tmp_path, bundle_json, ca_pem):
    bad = json.loads(json.dumps(bundle_json))
    bad["record"]["output_hash"] = "ab" * 32
    p = tmp_path / "b.json"
    p.write_text(json.dumps(bad), encoding="utf-8")
    ca = tmp_path / "ca.pem"
    ca.write_bytes(ca_pem)
    r = _cli(str(p), "--ca", str(ca))
    assert r.returncode == 1


def test_cli_json_output(tmp_path, bundle_json, ca_pem):
    p = tmp_path / "b.json"
    p.write_text(json.dumps(bundle_json), encoding="utf-8")
    ca = tmp_path / "ca.pem"
    ca.write_bytes(ca_pem)
    r = _cli(str(p), "--ca", str(ca), "--json")
    assert r.returncode == 0
    out = json.loads(r.stdout)
    assert out["ok"] is True
    assert len(out["checks"]) == TOTAL_CHECKS
    assert out["gen_time"] and out["tsa"]


# --- export_bundle 往返 ---------------------------------------------------

def test_export_bundle_roundtrip_keeps_token_out_of_the_epoch(tmp_path):
    """导出时把 token 从 epoch 里挪出来，epoch.tsa_token 置 None。
    这是自指规则在序列化层的落地：包里那个被哈希的 epoch 结构
    必须和当初提交给 TSA 的那个逐字节一致。"""
    from dataclasses import asdict

    from helpers import make_ledger
    from tg_attest.verify import export_bundle

    led = make_ledger()
    seal = led.seal_epoch()
    anchored = seal.epoch_hash()          # 提交给 TSA 的就是这个值
    led._epochs[0] = EpochSeal(**{**asdict(seal), "tsa_token": "ZmFrZQ=="})

    out = tmp_path / "d.json"
    export_bundle(led, 1, str(out))
    b = json.loads(out.read_text(encoding="utf-8"))

    assert b["epoch"]["tsa_token"] is None
    assert b["tsa_token"] == "ZmFrZQ=="
    # 往返之后重算，必须还是当初提交的那个哈希
    assert EpochSeal(**{**b["epoch"], "tsa_token": None}).epoch_hash() == anchored
    assert hash_obj(b["record"]) == b["record_hash"]
    assert "BEGIN CERTIFICATE" not in out.read_text(encoding="utf-8")


def test_verify_block_is_the_auditor_facing_contract(bundle):
    """_verify 块是给审计方看的说明书，内容属于披露格式的一部分。

    变异测试指出这一整块（spec / chain / openssl / note）没有任何断言
    盯着——里面的字符串随便改，测试全绿。它不影响密码学结论，
    但它是「拿到这个文件的人该怎么独立验证」的唯一线索，
    尤其是那句「不得使用本包内提供的任何证书」。
    """
    v = bundle["_verify"]
    assert v["spec"] == "tg-attest/1"
    assert v["chain"] == [
        "record→record_hash", "merkle proof→merkle_root",
        "epoch_hash(excl. tsa_token)", "TSA messageImprint",
        "TSA signature", "genTime",
    ]
    assert "openssl ts" in v["openssl"]
    assert "信任根" in v["note"] and "不得使用本包内" in v["note"]
