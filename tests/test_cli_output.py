"""不变量：CLI 打印的东西，和它的结论一致。

这个库的全部论点是「流畅的输出不等于真的验过」。输出层没有断言就是
自相矛盾——审计员实际看到的就是这几行字，而变异测试显示 cli.py 有
99 个变异体没有任何测试覆盖。

最重要的一条在最后：ok=False 时输出里不得出现「通过」二字，反之亦然。
一个把 ✗ 打成 ✓ 的 bug，在这个产品里和验证逻辑本身出错是同一级别的事故。
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from helpers import FIXTURES
from tg_attest.record import hash_obj
from tg_attest.verify import BUNDLE_REQUIRED_CHECKS


def run_cli(*args) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "tg_attest.cli", *args],
                          capture_output=True, text=True)


@pytest.fixture
def good(tmp_path):
    p = tmp_path / "b.json"
    p.write_text((FIXTURES / "decision_0000.json").read_text(encoding="utf-8"),
                 encoding="utf-8")
    ca = tmp_path / "ca.pem"
    ca.write_bytes((FIXTURES / "freetsa_ca.pem").read_bytes())
    return str(p), str(ca)


def broken(tmp_path, mutate) -> str:
    b = json.loads((FIXTURES / "decision_0000.json").read_text(encoding="utf-8"))
    mutate(b)
    p = tmp_path / "bad.json"
    p.write_text(json.dumps(b, ensure_ascii=False), encoding="utf-8")
    return str(p)


# --- 通过时的输出 ---------------------------------------------------------

def test_pass_output_header_lines(good):
    """头三行是决策本身的摘要：谁、什么模型、几条证据。
    审计员先看这个，再看下面的勾。"""
    path, ca = good
    r = run_cli(path, "--ca", ca)
    assert r.returncode == 0
    lines = r.stdout.splitlines()
    assert lines[0].startswith("决策 seq=0  决策时间 ")
    assert lines[1] == "  执行者 alpha-v2/pead  模型 claude-opus-5"
    assert lines[2] == "  证据 1 条，闸门 1 道"
    assert lines[3] == "通过"


def test_pass_output_lists_every_required_check_with_a_tick(good):
    """十项检查逐条打勾，一条不少。少打一条就是少显示一项结论。"""
    path, ca = good
    r = run_cli(path, "--ca", ca)
    for name in BUNDLE_REQUIRED_CHECKS:
        assert f"  ✓ {name}" in r.stdout, f"输出里缺少：{name}"
    assert r.stdout.count("  ✓ ") == len(BUNDLE_REQUIRED_CHECKS)


def test_pass_output_has_no_failure_markers(good):
    path, ca = good
    r = run_cli(path, "--ca", ca)
    assert "✗" not in r.stdout
    assert "!" not in r.stdout
    assert "必需检查未执行" not in r.stdout
    assert "失败" not in r.stdout


def test_pass_output_states_the_conclusion_and_the_signer(good):
    """结论那两行是这个工具真正的产出：某时刻之前就已存在，谁签的。"""
    path, ca = good
    r = run_cli(path, "--ca", ca)
    assert "TSA 签名时间：" in r.stdout
    assert "结论：该记录在 " in r.stdout
    assert " 之前即以此形态存在。" in r.stdout
    assert "时间由 " in r.stdout and " 签署。" in r.stdout
    assert "www.freetsa.org" in r.stdout


def test_gen_time_in_conclusion_matches_the_reported_signing_time(good):
    path, ca = good
    r = run_cli(path, "--ca", ca)
    sig = next(x for x in r.stdout.splitlines() if "TSA 签名时间：" in x)
    gen = sig.split("：", 1)[1].strip()
    concl = next(x for x in r.stdout.splitlines() if x.startswith("结论："))
    assert gen in concl, "结论里的时刻必须就是 TSA 签的那个"


# --- 失败时的输出 ---------------------------------------------------------

def test_failed_check_is_marked_with_a_cross(tmp_path, good):
    _, ca = good
    def mutate(b):
        b["record"]["output_hash"] = "ab" * 32
    r = run_cli(broken(tmp_path, mutate), "--ca", ca)
    assert r.returncode == 1
    assert "失败" in r.stdout
    assert "  ✗ 记录内容哈希自洽" in r.stdout


def test_failure_does_not_print_the_conclusion(tmp_path, good):
    """结论行只在通过时出现。失败了还打「该记录在 X 之前即以此形态存在」
    是这个工具能犯的最严重的显示错误。"""
    _, ca = good
    def mutate(b):
        b["record"]["output_hash"] = "ab" * 32
    r = run_cli(broken(tmp_path, mutate), "--ca", ca)
    assert "结论：" not in r.stdout
    assert "之前即以此形态存在" not in r.stdout


def test_missing_checks_are_shown_with_a_reason(good):
    """没给 --ca 时证书链那项根本没跑。它必须以 missing 的形式显示出来，
    而不是从列表里消失——消失就又回到了「少一项检查等于少一票反对」。"""
    path, _ = good
    r = run_cli(path)
    assert r.returncode == 1
    assert "  ? 时间戳/证书链至可信根 — 必需检查未执行" in r.stdout
    assert "  ! 未提供信任根，结论不可用于合规举证" in r.stdout
    assert "失败" in r.stdout


def test_profile_violation_is_named_in_the_output(tmp_path, good):
    """档案不满足时要说清楚是哪一条不满足，否则用户不知道该补什么。"""
    _, ca = good
    def mutate(b):
        b["record"]["evidence"] = []
        b["record_hash"] = hash_obj(b["record"])
    r = run_cli(broken(tmp_path, mutate), "--ca", ca)
    assert r.returncode == 1
    assert "  ✗ 记录满足所声明的完整性档案" in r.stdout
    assert "至少 1 条证据" in r.stdout
    assert "  ✓ 记录内容哈希自洽" in r.stdout, "哈希这一层本来就该通过"


def test_error_lines_are_prefixed(tmp_path, good):
    import base64
    _, ca = good
    def mutate(b):
        b["tsa_token"] = base64.b64encode(b"garbage").decode()
    r = run_cli(broken(tmp_path, mutate), "--ca", ca)
    assert r.returncode == 1
    assert any(x.startswith("  ! ") for x in r.stdout.splitlines())


# --- 核心一致性断言 -------------------------------------------------------

CASES = [
    ("valid", lambda b: None, 0),
    ("tampered-output", lambda b: b["record"].update(output_hash="ab" * 32), 1),
    ("tampered-evidence",
     lambda b: b["record"]["evidence"][0].update(as_of="2020-01-01T00:00:00+00:00"), 1),
    ("no-evidence", lambda b: (b["record"].update(evidence=[]),
                               b.update(record_hash=hash_obj(b["record"]))), 1),
    ("bad-token", lambda b: b.update(tsa_token="Z2FyYmFnZQ=="), 1),
    ("no-token", lambda b: b.pop("tsa_token"), 1),
    ("bad-proof", lambda b: b["proof"].__setitem__(0, ["L", "ab" * 32]), 1),
]


@pytest.mark.parametrize("name,mutate,expected_code", CASES,
                         ids=[c[0] for c in CASES])
def test_verdict_word_always_matches_exit_code(tmp_path, good, name, mutate,
                                               expected_code):
    """输出里的判定词和退出码必须永远一致。

    这是本文件最重要的一条。ok=False 时打印「通过」，或者 ok=True 时
    打印「失败」，等同于验证逻辑本身出错——审计员看的是字，CI 看的是
    退出码，两者说的必须是同一件事。
    """
    _, ca = good
    r = run_cli(broken(tmp_path, mutate), "--ca", ca)
    assert r.returncode == expected_code, r.stdout + r.stderr

    first_verdict = next(x for x in r.stdout.splitlines()
                         if x in ("通过", "失败"))
    if expected_code == 0:
        assert first_verdict == "通过"
        assert "失败" not in r.stdout
    else:
        assert first_verdict == "失败"
        # 「通过」只允许作为检查项名字的一部分出现，不能是独立的判定行
        assert "通过" not in r.stdout.splitlines()


@pytest.mark.parametrize("name,mutate,expected_code", CASES,
                         ids=[c[0] for c in CASES])
def test_json_ok_matches_exit_code(tmp_path, good, name, mutate, expected_code):
    _, ca = good
    r = run_cli(broken(tmp_path, mutate), "--ca", ca, "--json")
    assert r.returncode == expected_code
    payload = json.loads(r.stdout)
    assert payload["ok"] is (expected_code == 0)


# --- --json 结构 ----------------------------------------------------------

def test_json_shape_on_success(good):
    path, ca = good
    r = run_cli(path, "--ca", ca, "--json")
    assert r.returncode == 0
    p = json.loads(r.stdout)
    assert set(p) == {"ok", "checks", "missing", "gen_time", "tsa", "errors"}
    assert p["ok"] is True
    assert set(p["checks"]) == set(BUNDLE_REQUIRED_CHECKS)
    assert all(v is True for v in p["checks"].values())
    assert p["missing"] == []
    assert p["errors"] == []
    assert p["gen_time"].endswith("+00:00")
    assert "freetsa" in p["tsa"].lower()


def test_json_shape_without_ca(good):
    """missing 必须出现在 JSON 里，供 CI 抽检区分
    「跑了没过」和「压根没跑」——排查方向完全不同。"""
    path, _ = good
    r = run_cli(path, "--json")
    assert r.returncode == 1
    p = json.loads(r.stdout)
    assert p["ok"] is False
    assert p["missing"] == ["时间戳/证书链至可信根"]
    assert any("信任根" in e for e in p["errors"])


def test_json_is_parseable_even_on_failure(tmp_path, good):
    """失败时也必须是合法 JSON，否则 CI 里没法消费。"""
    _, ca = good
    def mutate(b):
        b["record"]["output_hash"] = "ab" * 32
    r = run_cli(broken(tmp_path, mutate), "--ca", ca, "--json")
    p = json.loads(r.stdout)
    assert p["ok"] is False
    assert p["checks"]["记录内容哈希自洽"] is False


def test_json_mode_prints_no_human_text(good):
    path, ca = good
    r = run_cli(path, "--ca", ca, "--json")
    assert "决策 seq=" not in r.stdout
    assert "结论：" not in r.stdout
    json.loads(r.stdout)                       # 整个 stdout 就是一个 JSON


# --- 参数与退出码 ---------------------------------------------------------

def test_missing_file_exits_nonzero(tmp_path, good):
    _, ca = good
    r = run_cli(str(tmp_path / "nope.json"), "--ca", ca)
    assert r.returncode != 0
    assert r.returncode != 0 and "通过" not in r.stdout


def test_malformed_json_exits_nonzero(tmp_path, good):
    _, ca = good
    p = tmp_path / "bad.json"
    p.write_text("{not json", encoding="utf-8")
    r = run_cli(str(p), "--ca", ca)
    assert r.returncode != 0
    assert "通过" not in r.stdout


def test_missing_ca_file_exits_nonzero(tmp_path, good):
    path, _ = good
    r = run_cli(path, "--ca", str(tmp_path / "nope.pem"))
    assert r.returncode != 0
    assert "通过" not in r.stdout


def test_help_mentions_the_ca_requirement():
    r = run_cli("--help")
    assert r.returncode == 0
    assert "--ca" in r.stdout
    assert "--json" in r.stdout


def test_no_arguments_exits_nonzero():
    r = run_cli()
    assert r.returncode != 0
