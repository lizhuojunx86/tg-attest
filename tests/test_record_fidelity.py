"""不变量：记录里存的，就是你交进去的那些东西。

这一组也是变异测试的产物，而且是这轮里最不该缺的一组。

Ledger.append() 的每一个字段赋值都可以被改成 None，整套测试照样全绿：

    actor=actor        → actor=None      仍然全绿
    model=model        → model=None      仍然全绿
    inputs_hash=hash_obj(inputs)  → inputs_hash=None   仍然全绿
    labels=labels or {}           → labels=None        仍然全绿

原因很直白：record_hash 是**在这些字段被写进去之后**算的，
所以一条把 actor 丢掉的记录，它的哈希、前向链、Merkle 根、时间戳
全都完全自洽。led.verify() 返回 []，验证器输出「通过」。

那正是这个库最坏的失败方式：一份密码学上无懈可击的证据，
证明的是一条内容已经丢失的记录。完整性不等于正确性——
哈希链保证「没被改过」，保证不了「一开始写对了」。
"""

from __future__ import annotations

import re
from dataclasses import asdict

import pytest

from helpers import make_ledger
from tg_attest.record import (
    EpochSeal,
    EvidenceRef,
    GateVerdict,
    Ledger,
    hash_obj,
    now_iso,
    verify_inclusion,
)

ACTOR = {"type": "human", "id": "reviewer-7"}
MODEL = {"provider": "anthropic", "id": "claude-opus-5",
         "version": "2026-06", "params_hash": "cfg-a1b2"}
INPUTS = {"application_id": "APP-88214"}
OUTPUT = {"decision": "refer", "confidence_band": "medium"}
LABELS = {"ticker": "AAPL", "desk": "credit"}


def one_record():
    led = Ledger()
    ev = EvidenceRef.of("bureau:score:APP-88214", {"score": "712"},
                        as_of="2026-05-02T20:00:00+00:00",
                        observed_at="2026-05-02T20:00:01.000+00:00")
    gate = GateVerdict("evidence_gate", "pass", {"lookahead_violations": 0})
    rec = led.append(actor=ACTOR, model=MODEL, inputs=INPUTS, output=OUTPUT,
                     evidence=[ev], gates=[gate], labels=LABELS,
                     output_ref="s3://bucket/APP-88214",
                     decided_at="2026-05-03T12:00:00.000+00:00")
    return led, rec, ev, gate


# --- append 的字段保真 ----------------------------------------------------

def test_append_preserves_actor_and_model():
    _, rec, _, _ = one_record()
    assert rec.actor == ACTOR
    assert rec.model == MODEL


def test_append_hashes_the_actual_inputs_and_output():
    """inputs_hash 必须真的是 inputs 的哈希，不是 None、不是别的东西的哈希。"""
    _, rec, _, _ = one_record()
    assert rec.inputs_hash == hash_obj(INPUTS)
    assert rec.output_hash == hash_obj(OUTPUT)
    assert rec.inputs_hash != rec.output_hash


def test_append_preserves_evidence_and_gates():
    _, rec, ev, gate = one_record()
    assert rec.evidence == [ev]
    assert rec.gates == [gate]
    assert rec.evidence[0].as_of == "2026-05-02T20:00:00+00:00"
    assert rec.evidence[0].observed_at == "2026-05-02T20:00:01.000+00:00"
    assert rec.evidence[0].value_hash == hash_obj({"score": "712"})


def test_append_preserves_labels_output_ref_and_decided_at():
    _, rec, _, _ = one_record()
    assert rec.labels == LABELS
    assert rec.output_ref == "s3://bucket/APP-88214"
    assert rec.decided_at == "2026-05-03T12:00:00.000+00:00"


def test_append_defaults_are_empty_not_none():
    """不传的字段应当是空容器，不是 None。None 会在 canonical json 里
    序列化成 null，和「这里没有东西」是两个不同的语义。"""
    led = Ledger()
    rec = led.append(actor=ACTOR, model=MODEL, inputs=INPUTS, output=OUTPUT,
                     decided_at="2026-05-03T12:00:00.000+00:00")
    assert rec.evidence == []
    assert rec.gates == []
    assert rec.labels == {}
    assert rec.output_ref is None


def test_decided_at_defaults_to_now_when_not_given():
    led = Ledger()
    rec = led.append(actor=ACTOR, model=MODEL, inputs=INPUTS, output=OUTPUT)
    assert rec.decided_at
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}\+00:00$",
                    rec.decided_at), rec.decided_at


def test_every_field_actually_participates_in_the_hash():
    """逐字段确认它进了哈希。漏掉任何一个，那个字段就是可以
    在事后随便改而查不出来的。"""
    _, rec, _, _ = one_record()
    body = rec.body()
    for field in ("seq", "prev_hash", "decided_at", "actor", "model",
                  "inputs_hash", "output_hash", "evidence", "gates",
                  "labels", "output_ref", "schema"):
        assert field in body, f"{field} 没有进入被哈希的 body"
    assert "record_hash" not in body
    assert rec.record_hash == hash_obj(body)


def test_recorded_content_survives_a_full_roundtrip():
    """写入 → 封存 → 披露 → 重新读出来，内容必须一字不差。"""
    led, rec, _, _ = one_record()
    led.seal_epoch()
    b = led.disclose(0)
    assert b["record"]["actor"] == ACTOR
    assert b["record"]["model"] == MODEL
    assert b["record"]["labels"] == LABELS
    assert b["record"]["evidence"][0]["as_of"] == "2026-05-02T20:00:00+00:00"
    assert Ledger.verify_disclosure(b) is True


def test_a_record_that_lost_a_field_is_still_cryptographically_self_consistent():
    """这条断言的是一个**弱点**，不是一个能力。

    手工造一条 actor 为 None 的记录，重算哈希、重建链——
    led.verify() 返回 []，整条链完全自洽。密码学挡不住这个，
    只有上面那些字段保真断言挡得住。
    """
    from tg_attest.record import DecisionRecord

    led, rec, _, _ = one_record()
    broken = asdict(rec)
    broken["actor"] = None
    broken["record_hash"] = ""
    tmp = DecisionRecord(**{**broken, "evidence": rec.evidence, "gates": rec.gates})
    led._records[0] = DecisionRecord(**{**broken, "evidence": rec.evidence,
                                        "gates": rec.gates,
                                        "record_hash": tmp.compute_hash()})
    assert led.verify() == [], "内容丢失但链自洽——这正是哈希链管不到的地方"
    assert led._records[0].actor is None


# --- seal_epoch 的字段保真 ------------------------------------------------

def test_seal_epoch_preserves_its_own_fields():
    led = make_ledger()
    seal = led.seal_epoch()
    assert seal.epoch_id == 0
    assert seal.start_seq == 0
    assert seal.end_seq == 2
    assert seal.sealed_at and seal.sealed_at.endswith("+00:00")
    assert seal.tsa_token is None


def test_second_epoch_gets_the_next_id_and_range():
    led = make_ledger()
    led.seal_epoch()
    led.append(actor=ACTOR, model=MODEL, inputs=INPUTS, output=OUTPUT,
               decided_at="2026-06-01T00:00:00.000+00:00")
    s1 = led.seal_epoch()
    assert s1.epoch_id == 1
    assert (s1.start_seq, s1.end_seq) == (3, 3)


# --- 多 epoch 披露 ---------------------------------------------------------

def test_disclose_from_an_earlier_epoch_uses_the_right_span_and_index():
    """跨 epoch 披露。之前所有披露测试都只有一个 epoch，
    于是 `seq - epoch.start_seq` 里的减号改成加号也测不出来
    （epoch 0 的 start_seq 是 0，加减一个样）。
    """
    led = Ledger()
    for i in range(7):
        led.append(actor=ACTOR, model=MODEL, inputs={"i": i}, output={"o": i},
                   decided_at=f"2026-06-{i + 1:02d}T00:00:00.000+00:00")
        if i in (2, 5):
            led.seal_epoch()

    assert [(e.start_seq, e.end_seq) for e in led._epochs] == [(0, 2), (3, 5)]

    for seq in range(6):
        b = led.disclose(seq)
        assert Ledger.verify_disclosure(b) is True, f"seq={seq} 的披露包验不过"
        assert b["record"]["seq"] == seq
        epoch = b["epoch"]
        assert epoch["start_seq"] <= seq <= epoch["end_seq"]

    # 第二个 epoch 里的记录，证明路径必须是针对那个 epoch 的根算的
    b = led.disclose(4)
    assert b["epoch"]["epoch_id"] == 1
    assert verify_inclusion(b["record_hash"], [tuple(p) for p in b["proof"]],
                            b["epoch"]["merkle_root"]) is True
    # 拿它去对另一个 epoch 的根，必须失败
    assert verify_inclusion(b["record_hash"], [tuple(p) for p in b["proof"]],
                            led._epochs[0].merkle_root) is False


def test_disclosing_an_unsealed_record_raises():
    led = Ledger()
    for i in range(4):
        led.append(actor=ACTOR, model=MODEL, inputs={"i": i}, output={"o": i},
                   decided_at=f"2026-06-{i + 1:02d}T00:00:00.000+00:00")
        if i == 2:
            led.seal_epoch()
    led.disclose(1)                                  # 已封存，可以
    with pytest.raises(ValueError, match="尚未封存"):
        led.disclose(3)                              # 还没封存


# --- 边界 -----------------------------------------------------------------

def test_epoch_end_seq_exactly_at_record_count_is_flagged():
    """end_seq == len(records) 是越界（合法上界是 len-1）。
    把判断写成 > 而不是 >= 就会漏掉这一个值。"""
    led = make_ledger()
    seal = led.seal_epoch()
    led._epochs[0] = EpochSeal(**{**asdict(seal), "end_seq": len(led._records)})
    assert any("不存在的记录" in p for p in led.verify())


def test_now_iso_is_utc_and_millisecond_precision():
    """now_iso 决定每条记录的 decided_at 默认值。掉了时区就是
    一个没有时区的时间戳，跨时区审计时说不清是几点。"""
    s = now_iso()
    assert s.endswith("+00:00"), s
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}\+00:00$", s), s


@pytest.mark.parametrize("side", ["", "r", "l", "X", None, 0])
def test_verify_inclusion_rejects_unknown_side_values(side):
    """side 只认 "L" / "R"。原来写成 `if side == "L" else 右`，
    于是任何非 "L" 的东西都被当成右兄弟——含义不明的输入应当拒绝，不是猜。"""
    led = make_ledger()
    led.seal_epoch()
    b = led.disclose(0)
    proof = [tuple(p) for p in b["proof"]]
    assert verify_inclusion(b["record_hash"], proof, b["epoch"]["merkle_root"])

    broken = [(side, sib) for _, sib in proof]
    assert verify_inclusion(b["record_hash"], broken,
                            b["epoch"]["merkle_root"]) is False


# --- evidence_index --------------------------------------------------------
# 变异测试指出这个函数一个测试都没有。它是 ReplayGate 的基础原语：
# 拿今天的值重算哈希、和历史 value_hash 比对，定位所有「依据已被修订」
# 的历史决策。没有它，本库最有差异化的那一层无从建起。

def test_evidence_index_groups_by_source_id():
    led = Ledger()
    for i, (src, val) in enumerate([("bureau:score:A", "700"),
                                    ("bureau:score:B", "650"),
                                    ("bureau:score:A", "712")]):
        led.append(actor=ACTOR, model=MODEL, inputs={"i": i}, output={"o": i},
                   evidence=[EvidenceRef.of(src, {"score": val},
                                            as_of="2026-05-02T20:00:00+00:00")],
                   gates=[GateVerdict("g", "pass", {})],
                   decided_at=f"2026-05-0{i + 1}T00:00:00.000+00:00",
                   profile="eu-ai-act")

    idx = led.evidence_index()
    assert set(idx) == {"bureau:score:A", "bureau:score:B"}
    assert [seq for seq, _ in idx["bureau:score:A"]] == [0, 2]
    assert [seq for seq, _ in idx["bureau:score:B"]] == [1]


def test_evidence_index_carries_the_evidence_objects():
    """返回的必须是 EvidenceRef 本身，不是副本或摘要——
    ReplayGate 要拿 value_hash 去比对。"""
    led = Ledger()
    ev = EvidenceRef.of("src:1", {"v": "1"}, as_of="2026-05-02T20:00:00+00:00")
    led.append(actor=ACTOR, model=MODEL, inputs={}, output={},
               evidence=[ev], gates=[GateVerdict("g", "pass", {})],
               decided_at="2026-05-01T00:00:00.000+00:00", profile="eu-ai-act")
    (seq, got), = led.evidence_index()["src:1"]
    assert seq == 0
    assert got == ev
    assert got.value_hash == hash_obj({"v": "1"})


def test_evidence_index_handles_multiple_evidence_per_record():
    led = Ledger()
    evs = [EvidenceRef.of(f"src:{i}", {"v": i}, as_of="2026-05-02T20:00:00+00:00")
           for i in range(3)]
    led.append(actor=ACTOR, model=MODEL, inputs={}, output={}, evidence=evs,
               gates=[GateVerdict("g", "pass", {})],
               decided_at="2026-05-01T00:00:00.000+00:00", profile="eu-ai-act")
    idx = led.evidence_index()
    assert len(idx) == 3
    assert all(len(v) == 1 and v[0][0] == 0 for v in idx.values())


def test_evidence_index_is_empty_for_records_without_evidence():
    led = Ledger()
    led.append(actor=ACTOR, model=MODEL, inputs={}, output={},
               decided_at="2026-05-01T00:00:00.000+00:00")
    assert led.evidence_index() == {}


def test_evidence_index_finds_every_decision_that_used_a_revised_source():
    """ReplayGate 的实际用法：某个数据源的值今天变了，
    哪些历史决策依赖过它。"""
    led = Ledger()
    for i in range(5):
        src = "fmp:earnings:AAPL:FY2026Q1" if i % 2 == 0 else "other:src"
        led.append(actor=ACTOR, model=MODEL, inputs={"i": i}, output={"o": i},
                   evidence=[EvidenceRef.of(src, {"eps": f"1.{i}"},
                                            as_of="2026-05-02T20:00:00+00:00")],
                   gates=[GateVerdict("g", "pass", {})],
                   decided_at=f"2026-05-0{i + 1}T00:00:00.000+00:00",
                   profile="eu-ai-act")

    affected = led.evidence_index()["fmp:earnings:AAPL:FY2026Q1"]
    assert [seq for seq, _ in affected] == [0, 2, 4]

    # 今天的值和当初记下的哈希不一致 → 这条决策的依据已被修订
    today = hash_obj({"eps": "9.9"})
    stale = [seq for seq, ev in affected if ev.value_hash != today]
    assert stale == [0, 2, 4]
