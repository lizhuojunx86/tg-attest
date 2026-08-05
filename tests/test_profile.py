"""不变量：一条记录必须满足它自称遵循的完整性档案。

这一组针对的是本产品类别的根本边界。

哈希链证明「这条记录没被改过」。它不证明「当初记全了」。集成方忘了传
evidence，你会得到一条 record_hash 正确、前向链完好、Merkle 根匹配、
TSA 签名有效的记录——里面什么证据都没有。led.verify() 返回 []，
验证器打印「通过」。密码学在这里帮不上任何忙：它保护内容的不变性，
不保护内容的存在性。

profile 把这个缺口从「不可见」变成两件具体的事：
  写入时  —— 不满足就抛 ProfileViolation，什么也不写进去
  验证时  —— 「记录满足所声明的完整性档案」是一项必需检查

档案名本身参与哈希，所以「我声明遵循 eu-ai-act」这句话事后改不动。

它挡不住什么：调用方本该用 eu-ai-act 却选了 minimal。本库无从判断，
诚实写在 docs/threat-model.md 里。
"""

from __future__ import annotations

import json

import pytest

from helpers import FIXTURES
from tg_attest.record import (
    DEFAULT_PROFILE,
    PROFILES,
    EvidenceRef,
    GateVerdict,
    Ledger,
    ProfileViolation,
    hash_obj,
    profile_violations,
)
from tg_attest.verify import BUNDLE_REQUIRED_CHECKS, verify_bundle

ACTOR = {"type": "agent", "id": "underwriting-v3"}
MODEL = {"provider": "anthropic", "id": "claude-opus-5", "params_hash": "cfg-a1b2"}
EV = [EvidenceRef.of("bureau:score:APP-1", {"score": "712"},
                     as_of="2026-05-02T20:00:00+00:00")]
GATES = [GateVerdict("evidence_gate", "pass", {"lookahead_violations": 0})]


def append(led: Ledger, **kw):
    base = dict(actor=ACTOR, model=MODEL, inputs={"a": 1}, output={"b": 2},
                decided_at="2026-05-03T12:00:00.000+00:00")
    return led.append(**{**base, **kw})


# --- 档案定义本身 ---------------------------------------------------------

def test_default_profile_is_minimal():
    assert DEFAULT_PROFILE == "minimal"
    assert append(Ledger()).profile == "minimal"


def test_known_profiles():
    assert set(PROFILES) == {"minimal", "eu-ai-act"}
    assert PROFILES["eu-ai-act"].require_evidence >= 1
    assert PROFILES["eu-ai-act"].require_gates >= 1


def test_profile_participates_in_the_record_hash():
    """否则「我声明遵循 eu-ai-act」这句话可以在审计前被悄悄降级成 minimal，
    而记录的哈希、链、时间戳全都不会变。"""
    led = Ledger()
    rec = append(led, evidence=EV, gates=GATES, profile="eu-ai-act")
    assert "profile" in rec.body()

    downgraded = {**rec.body(), "profile": "minimal"}
    assert hash_obj(downgraded) != rec.record_hash


# --- minimal：写入时校验 --------------------------------------------------

@pytest.mark.parametrize("field,value,expect", [
    ("actor", {"type": "agent"}, "actor.id"),
    ("actor", {"type": "agent", "id": ""}, "actor.id"),
    ("actor", {"type": "agent", "id": "   "}, "actor.id"),
    ("actor", {}, "actor.id"),
    ("model", {"provider": "x"}, "model.id"),
    ("model", {"provider": "x", "id": None}, "model.id"),
])
def test_minimal_rejects_missing_identity(field, value, expect):
    """少了 actor.id 或 model.id，这条记录回答不了「这是谁做的决定」。"""
    led = Ledger()
    with pytest.raises(ProfileViolation, match=expect):
        append(led, **{field: value})
    assert led._records == [], "校验失败时不能有任何东西被写进去"


def test_minimal_accepts_a_record_without_evidence():
    """minimal 不要求证据。这是刻意的——不是所有决策都有外部依据，
    强行要求只会让人填假数据。"""
    rec = append(Ledger())
    assert rec.evidence == []
    assert rec.profile_violations() == []


# --- eu-ai-act：写入时校验 ------------------------------------------------

def test_eu_profile_requires_evidence():
    """这一条就是 actor=None 那个发现的正面回答：
    声明了 eu-ai-act 却没有证据，写不进去。"""
    led = Ledger()
    with pytest.raises(ProfileViolation, match="至少 1 条证据"):
        append(led, gates=GATES, profile="eu-ai-act")
    assert led._records == []


def test_eu_profile_requires_gates():
    led = Ledger()
    with pytest.raises(ProfileViolation, match="至少 1 道闸门"):
        append(led, evidence=EV, profile="eu-ai-act")
    assert led._records == []


def test_eu_profile_accepts_a_complete_record():
    rec = append(Ledger(), evidence=EV, gates=GATES, profile="eu-ai-act")
    assert rec.profile == "eu-ai-act"
    assert rec.profile_violations() == []


@pytest.mark.parametrize("missing", ["source_id", "as_of", "observed_at", "value_hash"])
def test_eu_profile_requires_every_evidence_field(missing):
    """as_of / observed_at 缺了，evidence 就退化成「检索发生过」，
    和可观测工具没有区别了——那正是本库存在的理由。"""
    bad = EvidenceRef(**{**EV[0].__dict__, missing: ""})
    led = Ledger()
    with pytest.raises(ProfileViolation, match=missing):
        append(led, evidence=[bad], gates=GATES, profile="eu-ai-act")
    assert led._records == []


def test_eu_profile_checks_every_evidence_item_not_just_the_first():
    good, bad = EV[0], EvidenceRef(**{**EV[0].__dict__, "as_of": ""})
    with pytest.raises(ProfileViolation, match=r"evidence\[1\]"):
        append(Ledger(), evidence=[good, bad], gates=GATES, profile="eu-ai-act")


# --- 未知档案 -------------------------------------------------------------

@pytest.mark.parametrize("name", ["", "unknown", "EU-AI-ACT", "minimal ", None, 7])
def test_unknown_profile_is_rejected(name):
    """认不出的档案名不能当成「那就按最宽松的算」。"""
    with pytest.raises(ProfileViolation, match="未知的完整性档案"):
        append(Ledger(), profile=name)


def test_record_without_a_profile_field_fails_validation():
    """从旧格式 JSON 读出来的记录（没有 profile 字段）不算通过。
    这是 fail-closed：缺少声明不等于声明了最宽松的档案。"""
    assert profile_violations({"actor": {"id": "a"}, "model": {"id": "m"},
                               "inputs_hash": "x", "output_hash": "y"})


# --- 写入失败不留痕 -------------------------------------------------------

def test_failed_append_does_not_advance_the_chain():
    """校验失败之后，下一条成功的记录 seq 必须还是 0、prev_hash 还是创世。
    如果失败的那次已经动了状态，链就带上了一个看不见的洞。"""
    led = Ledger()
    with pytest.raises(ProfileViolation):
        append(led, profile="eu-ai-act")
    rec = append(led, evidence=EV, gates=GATES, profile="eu-ai-act")
    assert rec.seq == 0
    assert rec.prev_hash == "0" * 64
    assert len(led._records) == 1
    assert led.verify() == []


def test_mixed_profiles_in_one_ledger_are_fine():
    """同一个账本里可以混用档案。每条记录各自声明、各自被校验。"""
    led = Ledger()
    append(led, profile="minimal")
    append(led, evidence=EV, gates=GATES, profile="eu-ai-act")
    assert [r.profile for r in led._records] == ["minimal", "eu-ai-act"]
    assert led.verify() == []


# --- 验证路径 -------------------------------------------------------------

def test_profile_check_is_a_required_check():
    assert "记录满足所声明的完整性档案" in BUNDLE_REQUIRED_CHECKS


def test_shipped_fixture_declares_eu_ai_act_and_satisfies_it(bundle, ca_pem):
    """出厂 fixture 用的是严格档案，不是最宽松的那个——
    示例应当展示要求最高的用法。"""
    assert bundle["record"]["profile"] == "eu-ai-act"
    r = verify_bundle(bundle, ca_pem)
    assert r.ok is True
    assert r.checks["记录满足所声明的完整性档案"] is True


def test_bundle_claiming_eu_profile_with_no_evidence_fails_verification(bundle, ca_pem):
    """核心用例：一条声明了 eu-ai-act 但证据为空的记录，验证必须失败。

    构造时把 record_hash 一起重算，所以「记录内容哈希自洽」仍然通过——
    挡住它的只有档案检查这一项。密码学完好，内容是空的。
    """
    bundle["record"]["evidence"] = []
    bundle["record_hash"] = hash_obj(bundle["record"])

    r = verify_bundle(bundle, ca_pem)
    assert r.ok is False
    assert r.checks["记录内容哈希自洽"] is True, "哈希这一层本来就该通过"
    assert r.checks["记录满足所声明的完整性档案"] is False
    assert any("至少 1 条证据" in e for e in r.errors)


def test_bundle_with_downgraded_profile_fails_the_hash_check(bundle, ca_pem):
    """把 eu-ai-act 改成 minimal 想让空证据合规——档案名参与哈希，
    改了它内容哈希就对不上。两条路都堵死。"""
    bundle["record"]["profile"] = "minimal"
    r = verify_bundle(bundle, ca_pem)
    assert r.ok is False
    assert r.checks["记录内容哈希自洽"] is False


def test_bundle_with_unknown_profile_fails(bundle, ca_pem):
    bundle["record"]["profile"] = "made-up"
    bundle["record_hash"] = hash_obj(bundle["record"])
    r = verify_bundle(bundle, ca_pem)
    assert r.ok is False
    assert r.checks["记录满足所声明的完整性档案"] is False


def test_bundle_missing_the_profile_field_fails(bundle, ca_pem):
    del bundle["record"]["profile"]
    bundle["record_hash"] = hash_obj(bundle["record"])
    r = verify_bundle(bundle, ca_pem)
    assert r.ok is False
    assert r.checks["记录满足所声明的完整性档案"] is False


@pytest.mark.parametrize("field", ["as_of", "observed_at", "value_hash", "source_id"])
def test_bundle_with_an_incomplete_evidence_item_fails(bundle, ca_pem, field):
    bundle["record"]["evidence"][0][field] = ""
    bundle["record_hash"] = hash_obj(bundle["record"])
    r = verify_bundle(bundle, ca_pem)
    assert r.ok is False
    assert r.checks["记录满足所声明的完整性档案"] is False


def test_cli_reports_a_profile_violation(tmp_path, ca_pem):
    """审计员看到的东西：档案不满足时，CLI 必须说清楚是哪一条不满足。"""
    import subprocess
    import sys

    b = json.loads((FIXTURES / "decision_0000.json").read_text(encoding="utf-8"))
    b["record"]["gates"] = []
    b["record_hash"] = hash_obj(b["record"])
    p = tmp_path / "b.json"
    p.write_text(json.dumps(b), encoding="utf-8")
    ca = tmp_path / "ca.pem"
    ca.write_bytes(ca_pem)

    out = subprocess.run([sys.executable, "-m", "tg_attest.cli", str(p), "--ca", str(ca)],
                         capture_output=True, text=True)
    assert out.returncode == 1
    assert "✗ 记录满足所声明的完整性档案" in out.stdout
    assert "至少 1 道闸门" in out.stdout
    assert "通过" not in out.stdout.split("\n")[3]


# --- profile 挡不住什么（诚实记录） ---------------------------------------

def test_choosing_a_weaker_profile_is_not_detectable():
    """这条断言的是一个**限制**，不是能力。

    调用方本该用 eu-ai-act 却声明 minimal，本库无从判断——它不知道
    这个系统是不是高风险系统。一条 minimal 记录完全合规地缺少证据。
    profile 把「字段缺失」变成可见，把「档案选错」留在了外面。
    见 docs/threat-model.md。
    """
    led = Ledger()
    rec = append(led, profile="minimal")       # 本该是 eu-ai-act
    assert rec.evidence == []
    assert rec.profile_violations() == []      # 完全合规
    assert led.verify() == []
