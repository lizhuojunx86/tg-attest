"""不变量：ok 成立当且仅当必需检查清单逐项到齐且为 True，且没有 error。

这个文件存在的理由，是上一轮修的三个 fail-open 全都是同一个形状：
判定建立在「运行时攒出来的检查项」上，于是**检查项越少越容易通过**。
解析越早失败、走到的代码越少，结论越倾向于放行。

改成静态清单之后，形状反过来了：缺项即失败。下面这些用例逐项把每个
必需检查从结果里挖掉，断言 ok 一定变 False——所以以后谁加了新检查
却忘了注册进清单，或者谁把某一项悄悄从执行路径上摘掉，都会被抓住。
"""

from __future__ import annotations

import base64
import json

import pytest

from helpers import FIXTURES
from tg_attest.verify import (
    BUNDLE_REQUIRED_CHECKS,
    TOKEN_REQUIRED_CHECKS,
    VerifyResult,
    verify_bundle,
    verify_token,
)

# --- 清单本身 -------------------------------------------------------------

def test_required_check_lists_are_non_empty_and_unique():
    """空清单会让 conclude() 退化成「没有反对票就是通过」。"""
    assert TOKEN_REQUIRED_CHECKS
    assert len(set(TOKEN_REQUIRED_CHECKS)) == len(TOKEN_REQUIRED_CHECKS)
    assert len(set(BUNDLE_REQUIRED_CHECKS)) == len(BUNDLE_REQUIRED_CHECKS)


def test_bundle_list_contains_every_token_check():
    """bundle 清单必须完整包含 token 清单，否则「记录层过了、
    时间戳层少查一项」这种组合会溜过去。"""
    for c in TOKEN_REQUIRED_CHECKS:
        assert f"时间戳/{c}" in BUNDLE_REQUIRED_CHECKS


def test_actual_run_produces_exactly_the_required_checks(bundle, ca_pem):
    """真跑一遍，产出的检查项集合必须和清单一模一样。

    多出来的项说明有检查没注册进清单（不参与判定，等于白做）；
    少了的项说明清单里有永远跑不到的项（那 ok 就永远是 False）。
    """
    r = verify_bundle(bundle, ca_pem)
    assert set(r.checks) == set(BUNDLE_REQUIRED_CHECKS)
    assert r.missing == []


# --- 逐项挖掉：缺项必须导致失败 -------------------------------------------

@pytest.mark.parametrize("check", BUNDLE_REQUIRED_CHECKS)
def test_removing_any_required_check_flips_ok_to_false(bundle, ca_pem, check):
    """把某一项必需检查从结果里删掉，ok 必须变成 False 并记在 missing 里。

    这是整个改动的核心断言。旧的 all(checks.values()) 在这里会给出
    「通过」——少一项检查等于少一票反对。
    """
    r = verify_bundle(bundle, ca_pem)
    assert r.ok

    del r.checks[check]
    r.conclude(BUNDLE_REQUIRED_CHECKS)
    assert r.ok is False, f"删掉「{check}」之后仍然判通过"
    assert check in r.missing


@pytest.mark.parametrize("check", TOKEN_REQUIRED_CHECKS)
def test_removing_any_token_check_flips_ok_to_false(bundle, ca_pem, check):
    r = verify_token(base64.b64decode(bundle["tsa_token"]),
                     json_epoch_hash(bundle), ca_pem)
    assert r.ok

    del r.checks[check]
    r.conclude(TOKEN_REQUIRED_CHECKS)
    assert r.ok is False, f"删掉「{check}」之后仍然判通过"


@pytest.mark.parametrize("check", BUNDLE_REQUIRED_CHECKS)
def test_flipping_any_required_check_to_false_flips_ok(bundle, ca_pem, check):
    r = verify_bundle(bundle, ca_pem)
    r.checks[check] = False
    r.conclude(BUNDLE_REQUIRED_CHECKS)
    assert r.ok is False


@pytest.mark.parametrize("truthy", [1, "yes", "已跳过", [1], {"a": 1}, 0.1])
def test_only_literal_true_counts_as_pass(bundle, ca_pem, truthy):
    """必须是 True 本身，不是「真值」。字符串「已跳过（未提供 ca_bundle）」
    是真值——旧代码正是靠这个才没把跳过算成通过，纯属侥幸。"""
    r = verify_bundle(bundle, ca_pem)
    r.checks[BUNDLE_REQUIRED_CHECKS[0]] = truthy
    r.conclude(BUNDLE_REQUIRED_CHECKS)
    assert r.ok is False


# --- conclude() 的三个条件各自独立 ----------------------------------------

def test_empty_checks_is_not_a_pass():
    """all([]) 是 True。零项检查不能等于通过。"""
    r = VerifyResult(ok=False).conclude(TOKEN_REQUIRED_CHECKS)
    assert r.ok is False
    assert set(r.missing) == set(TOKEN_REQUIRED_CHECKS)


def test_errors_alone_are_enough_to_fail():
    """所有必需项齐全且为 True，但有 error —— 仍然不通过。"""
    r = VerifyResult(ok=False)
    r.checks = dict.fromkeys(TOKEN_REQUIRED_CHECKS, True)
    r.conclude(TOKEN_REQUIRED_CHECKS)
    assert r.ok is True                      # 基线：确认构造是对的

    r.errors.append("解析中途抛了个异常")
    r.conclude(TOKEN_REQUIRED_CHECKS)
    assert r.ok is False


def test_extra_checks_do_not_rescue_a_missing_required_one():
    """凑一堆无关的 True 进去，不能把缺失的必需项补上。"""
    r = VerifyResult(ok=False)
    r.checks = dict.fromkeys(TOKEN_REQUIRED_CHECKS, True)
    del r.checks[TOKEN_REQUIRED_CHECKS[0]]
    r.checks.update({f"无关检查{i}": True for i in range(20)})
    r.conclude(TOKEN_REQUIRED_CHECKS)
    assert r.ok is False


def json_epoch_hash(bundle: dict) -> str:
    from tg_attest.record import EpochSeal
    return EpochSeal(**{**bundle["epoch"], "tsa_token": None}).epoch_hash()


# --- 没有信任根时，证书链项应当是 missing 而不是被伪造成一条记录 ----------

def test_without_ca_the_chain_check_is_missing_not_faked(bundle):
    """旧代码往 checks 里写了个字符串「已跳过（未提供 ca_bundle）」。
    那等于伪造了一条「这项跑过了」的记录，只是值不是 True 而已。
    现在它就该是 missing——没跑就是没跑。"""
    r = verify_bundle(bundle, None)
    assert r.ok is False
    assert "时间戳/证书链至可信根" in r.missing
    assert "时间戳/证书链至可信根" not in r.checks
    assert any("信任根" in e for e in r.errors)


def test_str_output_shows_missing_checks(bundle):
    """人眼看到的输出里也必须有 missing。只在 JSON 里有等于没有。"""
    out = str(verify_bundle(bundle, None))
    assert "失败" in out
    assert "必需检查未执行" in out


def test_empty_ca_pem_is_not_a_pass(bundle, tmp_path):
    """传了一个解析不出任何证书的 PEM（空文件、传错文件）。
    这时错因是「没有信任根」，不是「链验不过」，要说清楚。"""
    r = verify_bundle(bundle, b"")
    assert r.ok is False
    assert any("没有解析出任何证书" in e for e in r.errors)


def test_cli_json_reports_missing(tmp_path):
    """CLI 的 JSON 输出必须带 missing 字段，供 CI 抽检消费。"""
    import subprocess
    import sys

    p = tmp_path / "b.json"
    p.write_text((FIXTURES / "decision_0000.json").read_text(encoding="utf-8"),
                 encoding="utf-8")
    out = subprocess.run([sys.executable, "-m", "tg_attest.cli", str(p), "--json"],
                         capture_output=True, text=True)
    assert out.returncode == 1
    payload = json.loads(out.stdout)
    assert payload["ok"] is False
    assert "时间戳/证书链至可信根" in payload["missing"]
