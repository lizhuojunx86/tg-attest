"""不变量：写入路径只用标准库。

这条不是洁癖。写入路径跑在生产决策热路径上——一个 crypto 库的版本冲突
不能拖垮部署。而且合规软件被采购时会审依赖树，依赖越少越好过。

最容易把这条作废的是 __init__.py 里的一行 import：
只要它在模块顶层 `from .verify import verify_bundle`，零依赖环境下
连 `import tg_attest` 都会当场 ImportError。所以下面用一个 meta_path
拦截器把 asn1crypto 和 cryptography 从子进程里彻底屏蔽掉，
在那种环境下跑一遍真实的 import。

CI 里另有一个 job 做同样的事，但方式更狠：在一个干净环境里
`pip install .`（不带 [tsa]），从而连包都不在磁盘上。
两者互补——这里挡回归，那里挡「本地碰巧装了」。
"""

from __future__ import annotations

import subprocess
import sys
import textwrap

import pytest

BLOCK = """
import sys

BLOCKED = {"asn1crypto", "cryptography"}

class Blocker:
    def find_spec(self, name, path=None, target=None):
        if name.split(".")[0] in BLOCKED:
            raise ImportError(f"{name} 被测试屏蔽：写入路径不允许依赖它")
        return None

sys.meta_path.insert(0, Blocker())

# 先确认屏蔽真的生效，否则下面全是假绿
try:
    import asn1crypto
except ImportError:
    pass
else:
    raise AssertionError("屏蔽没生效，这个测试什么也没证明")
"""


def run_blocked(body: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-c", BLOCK + textwrap.dedent(body)],
        capture_output=True, text=True,
    )


def test_record_imports_without_crypto_deps():
    r = run_blocked("import tg_attest.record; print('ok')")
    assert r.returncode == 0, r.stderr
    assert "ok" in r.stdout


def test_anchor_imports_without_crypto_deps():
    r = run_blocked("import tg_attest.anchor; print('ok')")
    assert r.returncode == 0, r.stderr
    assert "ok" in r.stdout


def test_package_root_imports_without_crypto_deps():
    """`import tg_attest` 本身也必须活着。这是最容易被一行
    顶层 import 悄悄作废的一条。"""
    r = run_blocked("import tg_attest; print('ok')")
    assert r.returncode == 0, r.stderr


def test_full_write_path_runs_without_crypto_deps():
    """不只是 import 成功，而是整条写入路径真的能跑完：
    追加记录、封存、算 Merkle 根、构造 TSQ 请求、选择性披露、自校验。"""
    r = run_blocked("""
        from tg_attest import Ledger, EvidenceRef, GateVerdict
        from tg_attest.anchor import build_tsq, AnchorQueue

        led = Ledger()
        led.append(
            actor={"type": "agent", "id": "underwriting-v3"},
            model={"provider": "anthropic", "id": "claude-opus-5",
                   "params_hash": "cfg-a1b2"},
            inputs={"application_id": "APP-88214"},
            output={"decision": "refer"},
            evidence=[EvidenceRef.of("bureau:score:APP-88214", {"score": "712"},
                                     as_of="2026-05-02T20:00:00+00:00")],
            gates=[GateVerdict("evidence_gate", "pass", {})],
        )
        seal = led.seal_epoch()
        assert led.verify() == []
        assert Ledger.verify_disclosure(led.disclose(0))

        q = AnchorQueue()
        q.enqueue(seal.epoch_id, seal.epoch_hash())
        assert len(q.pending) == 1

        tsq = build_tsq(bytes.fromhex(seal.epoch_hash()))
        assert tsq[0] == 0x30 and len(tsq) > 40
        print("ok")
    """)
    assert r.returncode == 0, r.stderr
    assert "ok" in r.stdout


def test_anchor_hash_write_time_check_degrades_without_deps():
    """写入时校验是软依赖。没装 [tsa] 时它必须整段跳过，
    而不是抛 ImportError 冲进生产决策路径。

    这里不打网络：直接调 _verify_at_write，断言它返回 (None, None)
    ——None 的语义是「没检查」，区别于 False 的「检查了没过」。
    """
    r = run_blocked("""
        from tg_attest.anchor import _verify_at_write
        verified, err = _verify_at_write(b"whatever", "ab" * 32, 12345)
        assert verified is None, f"应当跳过，实际 {verified!r}"
        assert err is None, err
        print("ok")
    """)
    assert r.returncode == 0, r.stderr
    assert "ok" in r.stdout


def test_anchor_still_ok_when_write_time_check_was_skipped():
    """verified_at_write=None（没检查）不能把 anchor 判成不可用；
    False（检查没过）必须判成不可用。这两者不能混为一谈。"""
    r = run_blocked("""
        from tg_attest.anchor import Anchor
        base = dict(epoch_id=0, anchored_hash="ab" * 32,
                    tsa_url="https://example/tsr", status="granted",
                    submitted_at="2026-08-04T00:00:00+00:00", token_b64="Zg==")
        assert Anchor(**base, verified_at_write=None).ok is True
        assert Anchor(**base, verified_at_write=True).ok is True
        assert Anchor(**base, verified_at_write=False).ok is False
        print("ok")
    """)
    assert r.returncode == 0, r.stderr


def test_verify_path_fails_with_a_useful_message():
    """验证路径在零依赖环境下必须失败——但要给出能照做的提示，
    而不是一个裸的 ModuleNotFoundError: No module named 'asn1crypto'。"""
    r = run_blocked("""
        import tg_attest
        try:
            tg_attest.verify_bundle
        except ImportError as e:
            assert "tg-attest[tsa]" in str(e), str(e)
            print("ok")
        else:
            raise AssertionError("零依赖环境下 verify_bundle 不该可用")
    """)
    assert r.returncode == 0, r.stderr
    assert "ok" in r.stdout


# 允许作为「软依赖」出现的第三方包：只能在函数体内 import，
# 且调用方必须处理 ImportError。模块顶层出现它们就是硬依赖，直接失败。
SOFT_DEPS = {"asn1crypto", "cryptography"}

WRITE_PATH_MODULES = ("record.py", "anchor.py", "eutl.py")


def _src_dir():
    """定位 src/tg_attest。

    跑变异测试时 mutmut 会把源码复制进 mutants/ 并注入自己的
    trampoline import，那份副本不该拿来做静态断言——下面几个用例
    检查的是**将要发布的源码**长什么样，不是被插桩过的临时副本。
    检测到插桩就 skip，理由说清楚，不要静默放过。
    """
    import pathlib

    for parent in pathlib.Path(__file__).resolve().parents:
        cand = parent / "src" / "tg_attest"
        if (cand / "record.py").is_file():
            if "mutmut" in (cand / "record.py").read_text(encoding="utf-8"):
                pytest.skip("源码被 mutmut 插桩过，静态检查对这份副本没有意义")
            return cand
    pytest.fail("找不到 src/tg_attest")


def _imports_by_scope(path):
    """把一个文件里的 import 分成「模块顶层」与「函数体内」两类。

    这个区分就是硬依赖和软依赖的区别：顶层 import 在 `import tg_attest.anchor`
    的那一刻就会执行，装不上就整个模块死掉；函数体内的 import 只在真正
    调用到那条路径时才执行，配上 try/except ImportError 就是可选增强。
    """
    import ast

    tree = ast.parse(path.read_text(encoding="utf-8"))
    in_function = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            for child in ast.walk(node):
                in_function.add(id(child))

    top, nested = [], []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [a.name.split(".")[0] for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level:              # 包内相对 import
                continue
            names = [(node.module or "").split(".")[0]]
        else:
            continue
        (nested if id(node) in in_function else top).extend(names)
    return top, nested


def test_write_path_has_no_module_level_third_party_import():
    """静态检查：写入路径模块的**顶层** import 只能来自标准库。

    比运行时检查更严——运行时能过只说明「当前代码路径」没碰到，
    这条管的是文件里出现过的每一个顶层 import 语句。
    """
    import sys as _sys

    stdlib = set(_sys.stdlib_module_names)
    src = _src_dir()

    for mod in WRITE_PATH_MODULES:
        top, _ = _imports_by_scope(src / mod)
        for n in top:
            assert n in stdlib, f"{mod} 顶层引入了非标准库依赖：{n}（会作废零依赖承诺）"


def test_write_path_function_local_imports_are_declared_soft_deps():
    """函数体内的第三方 import 只能是声明过的软依赖。

    不是「函数内 import 就随便」——那样只是把硬依赖藏得深一点，
    在零依赖环境下变成一个运行时炸弹而不是导入期错误。
    白名单之外的东西出现在这里，同样是失败。
    """
    import sys as _sys

    stdlib = set(_sys.stdlib_module_names)
    src = _src_dir()

    for mod in WRITE_PATH_MODULES:
        _, nested = _imports_by_scope(src / mod)
        for n in nested:
            assert n in stdlib or n in SOFT_DEPS, \
                f"{mod} 在函数内引入了未声明的第三方依赖：{n}"


def test_soft_dep_import_sites_handle_import_error():
    """每一处软依赖 import，调用链上必须有人接住 ImportError。

    anchor.py 的做法是 _inspect_token() 直接 import，
    _verify_at_write() 用 except ImportError 接住并降级为「跳过」。
    这条断言防的是有人后来把那个 except 删掉——静态上看不出问题，
    但零依赖环境下 anchor_hash() 会当场炸掉。
    """
    text = (_src_dir() / "anchor.py").read_text(encoding="utf-8")
    assert "except ImportError" in text, "anchor.py 里没有接住 ImportError 的地方"


@pytest.mark.parametrize("name", [
    "Ledger", "EvidenceRef", "GateVerdict", "DecisionRecord", "EpochSeal",
    "anchor_hash", "AnchorQueue",
])
def test_write_path_exports_are_eager(name):
    """写入路径的名字必须是真·立即可用，不能藏在 __getattr__ 后面
    然后在零依赖环境下炸掉。"""
    r = run_blocked(f"import tg_attest; assert tg_attest.{name}; print('ok')")
    assert r.returncode == 0, r.stderr


def test_no_traceguard_dependency():
    """两个项目的关系是数据结构兼容，不是代码依赖。"""
    for f in _src_dir().glob("*.py"):
        text = f.read_text(encoding="utf-8")
        assert "import traceguard" not in text
        assert "from traceguard" not in text
