"""不变量：verify_token / verify_bundle 的每一条 return 都经过 conclude()。

为什么这条要静态证明，而不是靠推断：

变异测试显示 `VerifyResult(ok=False)` → `ok=True` 存活。上一轮把它解释成
「初值是死代码，因为 conclude() 每条路径都会覆盖它」。那个解释是对的，
但它只是**一种**解释。同一个观察还有另一种解释：「那条提前返回的路径
没有被任何测试覆盖，所以初值被原样返回了也没人发现」。

两种解释在观察上完全等价——而第一个 fail-open（verify_bundle 对垃圾
token 判通过）恰恰就是一条提前返回的路径。用一个存活变异体去论证
「代码是安全的」，等于用「测试没抓到」去证明「没有东西可抓」。

所以这里直接对 AST 下断言：函数体里出现的每一个 return 语句，
返回值要么是 conclude() 调用，要么是一个已经被 conclude 过的变量。
推断不算证明。
"""

from __future__ import annotations

import ast
import inspect

import pytest

from tg_attest import verify as verify_mod

# 结论必须经过 conclude() 的函数
CONCLUDING_FUNCTIONS = ("verify_token", "verify_bundle")


def _func_ast(name: str) -> ast.FunctionDef:
    src = inspect.getsource(getattr(verify_mod, name))
    tree = ast.parse(inspect.cleandoc(src) if src.startswith(" ") else src)
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == name)
    return fn


def _returns(fn: ast.FunctionDef) -> list[ast.Return]:
    """函数体内的 return，不含嵌套函数里的。"""
    out, nested = [], set()
    for node in ast.walk(fn):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node is not fn:
            for child in ast.walk(node):
                nested.add(id(child))
    for node in ast.walk(fn):
        if isinstance(node, ast.Return) and id(node) not in nested:
            out.append(node)
    return out


def _is_conclude_call(node: ast.expr | None) -> bool:
    """形如 x.conclude(...) 的调用。"""
    return (isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "conclude")


@pytest.mark.parametrize("name", CONCLUDING_FUNCTIONS)
def test_function_has_at_least_one_return(name):
    """先确认解析确实找到了东西，否则下面的全称断言是空的。
    对空集合做 all() 永远为真——这个文件本身也得防这一手。"""
    assert _returns(_func_ast(name)), f"{name} 里没解析到任何 return"


@pytest.mark.parametrize("name", CONCLUDING_FUNCTIONS)
def test_every_return_goes_through_conclude(name):
    """核心断言：没有任何一条路径能绕过 conclude() 把结论交出去。"""
    fn = _func_ast(name)
    bad = []
    for node in _returns(fn):
        if node.value is None:
            bad.append((node.lineno, "裸 return"))
        elif not _is_conclude_call(node.value):
            bad.append((node.lineno, ast.unparse(node.value)))
    assert not bad, (
        f"{name} 里有 return 没有经过 conclude()：{bad}。"
        "提前返回是第一个 fail-open 的来源，不能再出现。")


@pytest.mark.parametrize("name", CONCLUDING_FUNCTIONS)
def test_conclude_is_always_called_with_a_required_list(name):
    """conclude() 必须收到一份必需清单常量，不能是空的或字面量。
    conclude([]) 会让判定退化回「没有反对票就是通过」。"""
    fn = _func_ast(name)
    allowed = {"TOKEN_REQUIRED_CHECKS", "BUNDLE_REQUIRED_CHECKS"}
    seen = 0
    for node in ast.walk(fn):
        if _is_conclude_call(node):
            seen += 1
            assert len(node.args) == 1, f"{name}:{node.lineno} conclude() 参数个数不对"
            arg = node.args[0]
            assert isinstance(arg, ast.Name) and arg.id in allowed, \
                f"{name}:{node.lineno} conclude() 收到的不是必需清单：{ast.unparse(arg)}"
    assert seen, f"{name} 里没有 conclude() 调用"


@pytest.mark.parametrize("name", CONCLUDING_FUNCTIONS)
def test_ok_is_never_assigned_outside_conclude(name):
    """函数体里不得直接给 r.ok 赋值。旧代码正是靠
    `r.ok = all(...)` 在 conclude 之外算结论的。"""
    fn = _func_ast(name)
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Attribute) and t.attr == "ok":
                    pytest.fail(f"{name}:{node.lineno} 直接给 .ok 赋值，"
                                "结论必须只由 conclude() 产生")


def test_conclude_is_the_only_place_that_sets_ok():
    """整个模块范围内，只有 VerifyResult.conclude 会写 .ok。"""
    tree = ast.parse(inspect.getsource(verify_mod))
    conclude_fn = next(n for n in ast.walk(tree)
                       if isinstance(n, ast.FunctionDef) and n.name == "conclude")
    inside = {id(c) for c in ast.walk(conclude_fn)}

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and id(node) not in inside:
            for t in node.targets:
                if isinstance(t, ast.Attribute) and t.attr == "ok":
                    pytest.fail(f"verify.py:{node.lineno} 在 conclude 之外写了 .ok")


def test_conclude_computes_ok_from_all_three_conditions():
    """conclude() 自身必须同时用到 missing、checks、errors。
    少任何一个都是一种已经犯过的 fail-open：
      少 missing —— 缺项不算失败
      少 errors  —— 异常被吞掉之后仍然判通过
    """
    src = inspect.getsource(verify_mod.VerifyResult.conclude)
    for token in ("self.missing", "self.checks", "self.errors"):
        assert token in src, f"conclude() 没有用到 {token}"


def test_all_public_entry_points_return_a_concluded_result(bundle, ca_pem):
    """静态断言之外再走一遍动态：几条典型路径拿到的结果，
    ok 都必须和按清单重算的结论一致——即 conclude 确实跑过。"""
    import base64
    import copy

    from tg_attest.verify import (
        BUNDLE_REQUIRED_CHECKS,
        TOKEN_REQUIRED_CHECKS,
        verify_bundle,
        verify_token,
    )

    def recompute(r, required):
        return (not [c for c in required if c not in r.checks]
                and all(r.checks.get(c) is True for c in required)
                and not r.errors)

    cases = [
        (verify_bundle(copy.deepcopy(bundle), ca_pem), BUNDLE_REQUIRED_CHECKS),
        (verify_bundle(copy.deepcopy(bundle), None), BUNDLE_REQUIRED_CHECKS),
        (verify_bundle({"record": {}, "record_hash": "x", "proof": [],
                        "epoch": {}}, ca_pem), BUNDLE_REQUIRED_CHECKS),
        (verify_token(b"", "ab" * 32, ca_pem), TOKEN_REQUIRED_CHECKS),
        (verify_token(base64.b64decode(bundle["tsa_token"]), "ab" * 32, ca_pem),
         TOKEN_REQUIRED_CHECKS),
    ]
    for r, required in cases:
        assert r.ok == recompute(r, required)
        assert r.missing == [c for c in required if c not in r.checks]


def test_a_bundle_missing_tsa_token_still_returns_concluded_result(bundle, ca_pem):
    """这条是第一个 fail-open 的直接形状：提前 return 的路径。"""
    from tg_attest.verify import BUNDLE_REQUIRED_CHECKS, verify_bundle

    del bundle["tsa_token"]
    r = verify_bundle(bundle, ca_pem)
    assert r.ok is False
    assert r.missing, "提前返回的路径也必须填好 missing"
    assert set(r.missing) <= set(BUNDLE_REQUIRED_CHECKS)
