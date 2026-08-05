"""不变量：任何参与被哈希内容的字段，都不得包含该哈希的结果。

具体到这里：epoch_hash() 必须排除 tsa_token。

这类自指是哈希链最隐蔽的一类 bug，而且失败方式极其难查——
提交 epoch_hash 给 TSA、取回 token、回写进 EpochSeal，如果 token 参与
哈希，epoch_hash 当场变成另一个值，那个刚花钱盖的时间戳锚定的是一个
再也不会出现的哈希。链自洽，token 有效签名，两者就是对不上。
几个月后审计时才会发现，而那时已经没法补盖了。

record_hash 不参与自身计算是同一条规则的另一个实例。
"""

from __future__ import annotations

from dataclasses import asdict

import pytest

from helpers import make_ledger
from tg_attest.record import GENESIS, EpochSeal, Ledger


def token_written_back(seal: EpochSeal, token: str = "ZmFrZS10b2tlbg==") -> EpochSeal:
    return EpochSeal(**{**asdict(seal), "tsa_token": token})


# --- 核心不变量 -----------------------------------------------------------

def test_epoch_hash_is_unchanged_by_writing_back_the_token():
    led = make_ledger()
    seal = led.seal_epoch()
    before = seal.epoch_hash()
    after = token_written_back(seal).epoch_hash()
    assert after == before, "回写 tsa_token 改变了 epoch_hash，时间戳当场失效"


@pytest.mark.parametrize("token", [
    None,
    "",
    "ZmFrZS10b2tlbg==",
    "A" * 8000,                       # 真 token 是几 KB
    "另一个完全不同的 token",
])
def test_epoch_hash_is_independent_of_token_value(token):
    """不只是「回写不变」，而是对 token 的取值完全不敏感。"""
    led = make_ledger()
    seal = led.seal_epoch()
    assert EpochSeal(**{**asdict(seal), "tsa_token": token}).epoch_hash() \
        == seal.epoch_hash()


def test_epoch_hash_does_depend_on_everything_else():
    """排除 tsa_token 是唯一的豁免。其余每个字段都必须参与，
    否则那个字段就可以在锚定之后被随便改。"""
    led = make_ledger()
    seal = led.seal_epoch()
    base = seal.epoch_hash()
    for field, value in [("epoch_id", 99),
                         ("start_seq", 1),
                         ("end_seq", 1),
                         ("merkle_root", "ab" * 32),
                         ("prev_epoch_hash", "cd" * 32),
                         ("sealed_at", "2020-01-01T00:00:00.000+00:00")]:
        assert EpochSeal(**{**asdict(seal), field: value}).epoch_hash() != base, field


def test_record_hash_is_not_part_of_its_own_input():
    """同一条规则在记录层面的实例：compute_hash() 不吃 record_hash。"""
    led = make_ledger()
    rec = led._records[0]
    assert rec.record_hash == rec.compute_hash()
    assert "record_hash" not in rec.body()


# --- 回写后整条链仍然成立 -------------------------------------------------

def test_ledger_still_verifies_after_token_writeback():
    led = make_ledger()
    seal = led.seal_epoch()
    led._epochs[0] = token_written_back(seal)
    assert led.verify() == []


def test_epoch_chain_survives_token_writeback_on_earlier_epoch():
    """两个 epoch：给第一个回写 token 之后，第二个的 prev_epoch_hash
    必须仍然对得上。prev_epoch_hash 是在封存时就算好的，如果 epoch_hash
    会被 token 影响，这里就会断。"""
    led = make_ledger()
    seal0 = led.seal_epoch()
    led.append(actor={"type": "agent", "id": "x"},
               model={"provider": "p", "id": "m", "version": "1", "params_hash": "h"},
               inputs={"q": "1"}, output={"a": "2"},
               decided_at="2026-05-09T12:00:00.000+00:00")
    seal1 = led.seal_epoch()
    assert seal1.prev_epoch_hash == seal0.epoch_hash()

    led._epochs[0] = token_written_back(seal0)
    assert led.verify() == []
    assert led._epochs[1].prev_epoch_hash == led._epochs[0].epoch_hash()


def test_first_epoch_links_to_genesis():
    led = make_ledger()
    assert led.seal_epoch().prev_epoch_hash == GENESIS


# --- 封存语义 -------------------------------------------------------------

def test_sealing_twice_without_new_records_raises():
    led = make_ledger()
    led.seal_epoch()
    with pytest.raises(ValueError, match="没有新记录"):
        led.seal_epoch()


def test_epochs_partition_the_records():
    """epoch 之间不重叠、不留缝。留缝就意味着有记录没被任何 Merkle 根覆盖，
    那些记录可以随便改。"""
    led = Ledger()
    seals = []
    for i in range(6):
        led.append(actor={"type": "agent", "id": "x"},
                   model={"provider": "p", "id": "m", "version": "1",
                          "params_hash": "h"},
                   inputs={"i": i}, output={"o": i},
                   decided_at=f"2026-05-{i + 10:02d}T12:00:00.000+00:00")
        if i % 2 == 1:
            seals.append(led.seal_epoch())

    assert seals[0].start_seq == 0
    for prev, cur in zip(seals, seals[1:], strict=False):
        assert cur.start_seq == prev.end_seq + 1, "epoch 之间有缝或有重叠"
    assert seals[-1].end_seq == len(led._records) - 1
    assert led.verify() == []


def test_epoch_chain_break_is_detected():
    led = make_ledger()
    seal0 = led.seal_epoch()
    led.append(actor={"type": "agent", "id": "x"},
               model={"provider": "p", "id": "m", "version": "1", "params_hash": "h"},
               inputs={"q": "1"}, output={"a": "2"},
               decided_at="2026-05-09T12:00:00.000+00:00")
    led.seal_epoch()
    led._epochs[1] = EpochSeal(**{**asdict(led._epochs[1]),
                                  "prev_epoch_hash": "00" * 32})
    assert any("周期链断裂" in p for p in led.verify())
    assert seal0.epoch_hash() != "00" * 32


def test_merkle_root_covers_exactly_the_epoch_span():
    from tg_attest.record import merkle_root
    led = make_ledger()
    seal = led.seal_epoch()
    span = [r.record_hash for r in led._records[seal.start_seq:seal.end_seq + 1]]
    assert seal.merkle_root == merkle_root(span)
