"""不变量：三类篡改，每一类都有且只有一层结构能抓住它。

这三个场景是递进的，也是整个设计的论证过程：

  A 只改内容            → 单条自校验抓住（record_hash 对不上）
  B 改内容并重算哈希    → 单条自校验失效，前向链抓住（prev_hash 对不上）
  C 改最后一条并重算    → 前向链也失效（后面没有记录），
                          只剩已封存的 Merkle 根能抓住

C 是关键的一条。它说明为什么光有哈希链不够：一个有写权限的人可以
从任意位置往后整段重建，链依然自洽。只有把 epoch 根交给一个不受你
控制的第三方签名，「这批记录在时刻 T 之前就已存在」才成为可以对抗
你自己的断言。没有第 4 步的锚定，A/B/C 全都只是「防外人」。
"""

from __future__ import annotations

import pytest

from helpers import make_ledger, rewrite
from tg_attest.record import EvidenceRef, GateVerdict, Ledger, hash_obj

# --- 干净的账本 -----------------------------------------------------------

def test_clean_ledger_verifies():
    led = make_ledger()
    assert led.verify() == []
    led.seal_epoch()
    assert led.verify() == []


def test_verify_returns_problems_it_does_not_raise():
    """审计要的是「哪几条被动过」，不是第一条就中断。"""
    led = make_ledger()
    led._records[0] = rewrite(led._records[0], output_hash=hash_obj({"x": 1}))
    problems = led.verify()
    assert isinstance(problems, list) and problems


# --- 场景 A：只改内容 -----------------------------------------------------

def test_A_content_only_caught_by_record_hash():
    """把 MSFT 的仓位从 40bps 改成 400bps，不动 record_hash。"""
    led = make_ledger()
    led._records[1] = rewrite(led._records[1],
                              output_hash=hash_obj({"action": "BUY", "size_bps": 400}))
    problems = led.verify()
    assert any("内容被篡改" in p and "seq 1" in p for p in problems), problems
    # 后一条的 prev_hash 指向的是没变的 record_hash，所以前向链没断。
    # 这正是「单条自校验」这一层独立存在的意义。
    assert not any("前向链断裂" in p for p in problems), problems


@pytest.mark.parametrize("field,value", [
    ("decided_at", "2026-01-01T00:00:00.000+00:00"),
    ("inputs_hash", "ab" * 32),
    ("output_hash", "cd" * 32),
    ("actor", {"type": "human", "id": "someone-else"}),
    ("model", {"provider": "other", "id": "gpt", "version": "x", "params_hash": "y"}),
    ("labels", {"ticker": "TSLA"}),
    ("output_ref", "s3://elsewhere"),
    ("seq", 99),
])
def test_A_any_field_change_is_caught(field, value):
    """记录里每一个字段都参与哈希。漏掉任何一个，那个字段就是可以
    随便改的——审计场景下没有「这个字段不重要」这回事。"""
    led = make_ledger()
    led._records[1] = rewrite(led._records[1], **{field: value})
    assert led.verify() != []


def test_A_evidence_tampering_is_caught():
    """证据的 as_of 是本库的核心字段，改它等于伪造「当时看到的是什么」。"""
    led = make_ledger()
    old = led._records[1].evidence[0]
    forged = EvidenceRef(source_id=old.source_id,
                         as_of="2026-05-03T20:00:00+00:00",   # 往后挪一天
                         observed_at=old.observed_at,
                         value_hash=old.value_hash)
    led._records[1] = rewrite(led._records[1], evidence=[forged])
    assert any("内容被篡改" in p for p in led.verify())


def test_A_gate_verdict_tampering_is_caught():
    """把闸门的 fail 改成 pass —— 「我们当时检查过了」是最值钱的谎。"""
    led = make_ledger()
    led._records[1] = rewrite(
        led._records[1],
        gates=[GateVerdict("evidence_gate", "fail", {"lookahead_violations": 3})])
    assert any("内容被篡改" in p for p in led.verify())


# --- 场景 B：改内容并重算 record_hash -------------------------------------

def test_B_resealed_middle_record_caught_by_forward_chain():
    """聪明的篡改者：改完内容顺手把 record_hash 也重算了。
    单条自校验当场失效，抓住它的是下一条记录里的 prev_hash。"""
    led = make_ledger()
    led._records[1] = rewrite(led._records[1], reseal=True,
                              output_hash=hash_obj({"action": "BUY", "size_bps": 400}))
    problems = led.verify()
    assert not any("seq 1: 内容被篡改" in p for p in problems), problems
    assert any("seq 2" in p and "前向链断裂" in p for p in problems), problems


def test_B_rebuilding_the_whole_tail_defeats_the_chain():
    """把 seq=1 改掉之后，连 seq=2 一起重建——链就完全自洽了。

    这条测试断言的是一个『失败』：没有外部锚定时，有写权限的人可以
    重写历史而不留痕迹。整个 anchor.py 存在的理由就是这一行 assert。
    """
    led = make_ledger()
    led._records[1] = rewrite(led._records[1], reseal=True,
                              output_hash=hash_obj({"action": "BUY", "size_bps": 400}))
    led._records[2] = rewrite(led._records[2], reseal=True,
                              prev_hash=led._records[1].record_hash)
    assert led.verify() == [], "重建整条尾部后链应当自洽——这正是问题所在"


def test_B_but_a_sealed_epoch_still_catches_the_rebuild():
    """同样的重建，只要 epoch 已经封存过，Merkle 根就对不上了。"""
    led = make_ledger()
    led.seal_epoch()
    led._records[1] = rewrite(led._records[1], reseal=True,
                              output_hash=hash_obj({"action": "BUY", "size_bps": 400}))
    led._records[2] = rewrite(led._records[2], reseal=True,
                              prev_hash=led._records[1].record_hash)
    assert any("Merkle 根不匹配" in p for p in led.verify())


# --- 场景 C：改最后一条 ---------------------------------------------------

def test_C_last_record_resealed_is_invisible_without_a_seal():
    """改最后一条并重算哈希：后面没有记录，前向链完好；单条自校验也过了。
    未封存时，这条篡改在账本内部完全不可见。"""
    led = make_ledger()
    led._records[2] = rewrite(led._records[2], reseal=True,
                              output_hash=hash_obj({"action": "BUY", "size_bps": 40}))
    assert led.verify() == [], "未封存时改最后一条应当查不出来"


def test_C_last_record_resealed_is_caught_by_the_sealed_merkle_root():
    """封存之后，同样的篡改被 Merkle 根抓住——而那个根已经被 TSA 签名，
    篡改者无法重建。这就是锚定买到的东西。"""
    led = make_ledger()
    led.seal_epoch()
    led._records[2] = rewrite(led._records[2], reseal=True,
                              output_hash=hash_obj({"action": "BUY", "size_bps": 40}))
    problems = led.verify()
    assert not any("内容被篡改" in p for p in problems), problems
    assert not any("前向链断裂" in p for p in problems), problems
    assert any("Merkle 根不匹配" in p for p in problems), problems


# --- 删除与重排 -----------------------------------------------------------

def test_deleting_a_record_is_caught():
    led = make_ledger()
    led.seal_epoch()
    del led._records[1]
    assert led.verify() != []


def test_truncating_the_tail_is_caught_after_sealing():
    """删掉末尾的记录不会破坏前向链——只有已封存的 Merkle 根能抓住。"""
    led = make_ledger()
    led.seal_epoch()
    led._records.pop()
    problems = led.verify()
    assert any("Merkle 根不匹配" in p for p in problems), problems


def test_reordering_is_caught():
    led = make_ledger()
    led._records[0], led._records[1] = led._records[1], led._records[0]
    assert led.verify() != []


def test_appending_a_forged_record_is_caught():
    """伪造一条追加记录，prev_hash 随便填。"""
    led = make_ledger()
    forged = rewrite(led._records[2], reseal=True, seq=3, prev_hash="00" * 32)
    led._records.append(forged)
    assert any("前向链断裂" in p for p in led.verify())


# --- 披露包层面的篡改 -----------------------------------------------------

def test_disclosure_of_a_tampered_record_fails_third_party_check():
    led = make_ledger()
    led.seal_epoch()
    b = led.disclose(1)
    b["record"]["output_hash"] = hash_obj({"action": "BUY", "size_bps": 400})
    assert Ledger.verify_disclosure(b) is False


def test_disclosure_with_recomputed_record_hash_still_fails():
    """改内容并把 record_hash 一起改掉——包含证明这一层挡住它。"""
    led = make_ledger()
    led.seal_epoch()
    b = led.disclose(1)
    b["record"]["output_hash"] = hash_obj({"action": "BUY", "size_bps": 400})
    b["record_hash"] = hash_obj(b["record"])
    assert Ledger.verify_disclosure(b) is False


def test_clean_disclosure_passes():
    led = make_ledger()
    led.seal_epoch()
    for seq in range(3):
        assert Ledger.verify_disclosure(led.disclose(seq)) is True


def test_disclose_before_sealing_raises():
    led = make_ledger()
    with pytest.raises(ValueError, match="尚未封存"):
        led.disclose(0)
