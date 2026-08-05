"""测试用的账本构造与篡改工具。

放在独立模块而不是 conftest.py：这些是普通函数不是 fixture，
而 `from conftest import ...` 依赖 pytest 的 sys.path 插入行为，
换个 importmode 就会断。tests/ 目录本身会被 prepend 进 sys.path，
所以 `from helpers import ...` 是稳的。
"""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from tg_attest.record import DecisionRecord, EvidenceRef, GateVerdict, Ledger


def fixtures_dir() -> Path:
    """向上找 fixtures/ 目录，不写死相对层级。

    写死 __file__.parent.parent / "fixtures" 在变异测试下会挂：mutmut 把
    源码和测试复制进 mutants/ 再在那里跑，此时上两级是 mutants/ 而不是仓库根。
    往上走到找见为止，测试就不再依赖自己被放在哪一层。
    """
    for parent in Path(__file__).resolve().parents:
        cand = parent / "fixtures"
        if (cand / "decision_0000.json").is_file():
            return cand
    raise RuntimeError("找不到 fixtures/ 目录")


FIXTURES = fixtures_dir()

# 固定的 decided_at，让整套测试可复现——不用 now()，否则每次跑出来的
# record_hash 都不同，没法对任何具体值做断言。
ROWS = [("AAPL", "1.5300", "BUY"), ("MSFT", "2.9400", "BUY"), ("NVDA", "0.8100", "HOLD")]


def make_ledger(n: int = 3) -> Ledger:
    led = Ledger()
    for i, (tic, eps, act) in enumerate(ROWS[:n]):
        led.append(
            actor={"type": "agent", "id": "alpha-v2/pead"},
            model={"provider": "anthropic", "id": "claude-opus-5",
                   "version": "2026-06", "params_hash": "cfg-a1b2"},
            inputs={"question": f"{tic} 财报后仓位决策"},
            output={"action": act, "size_bps": 40},
            evidence=[EvidenceRef.of(f"fmp:earnings:{tic}:FY2026Q1",
                                     {"epsActual": eps},
                                     as_of="2026-05-02T20:00:00+00:00",
                                     observed_at="2026-05-02T20:00:01.000+00:00")],
            gates=[GateVerdict("evidence_gate", "pass", {"lookahead_violations": 0})],
            labels={"ticker": tic},
            decided_at=f"2026-05-0{i + 3}T12:00:00.000+00:00",
        )
    return led


def rewrite(rec: DecisionRecord, *, reseal: bool = False, **changes) -> DecisionRecord:
    """改一条记录。reseal=True 表示篡改者顺手把 record_hash 也重算了。"""
    d = asdict(rec)
    d.update(changes)
    # asdict 会把 evidence/gates 递归拆成 dict，这里换回 dataclass 实例。
    # 哈希结果两者相同（body() 又会 asdict 一次），但类型保持正确更省事。
    if "evidence" not in changes:
        d["evidence"] = rec.evidence
    if "gates" not in changes:
        d["gates"] = rec.gates
    if reseal:
        d["record_hash"] = ""
        d["record_hash"] = DecisionRecord(**d).compute_hash()
    return DecisionRecord(**d)
