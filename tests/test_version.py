"""不变量：版本号只有一个来源，而且和 git tag、CHANGELOG 对得上。

之前 pyproject.toml、__init__.py、CHANGELOG.md 三处各写一遍 0.1.0，
靠人盯着对齐。那种约定迟早会漂——发布时改了两处忘了第三处，
装出来的包报的版本和 CHANGELOG 说的不是一回事。

对一个讲「记录必须和事实一致」的库来说，自己的版本号对不上很难解释。
现在唯一来源是 git tag，setuptools-scm 推导，__version__ 从包元数据读。
这个文件负责保证那条链没断。
"""

from __future__ import annotations

import re
import subprocess
import tomllib

import pytest

import tg_attest
from helpers import FIXTURES

ROOT = FIXTURES.parent
CHANGELOG = ROOT / "CHANGELOG.md"
PYPROJECT = ROOT / "pyproject.toml"


def git(*args) -> tuple[int, str]:
    r = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True)
    return r.returncode, r.stdout.strip()


def release_part(v: str) -> str:
    """0.1.1.dev3+g1234 → 0.1.1"""
    return re.match(r"^(\d+\.\d+\.\d+)", v).group(1)


def is_clean_release(v: str) -> bool:
    return re.fullmatch(r"\d+\.\d+\.\d+", v) is not None


# --- 单一来源 -------------------------------------------------------------

def test_version_is_dynamic_in_pyproject():
    """pyproject 里不能再有写死的 version。"""
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    assert "version" in data["project"].get("dynamic", []), \
        "project.version 应当是 dynamic，由 setuptools-scm 从 tag 推导"
    assert "version" not in data["project"], "pyproject 里还有写死的 version"


def init_ast():
    import ast
    return ast.parse((ROOT / "src" / "tg_attest" / "__init__.py")
                     .read_text(encoding="utf-8"))


def test_init_does_not_hardcode_a_version():
    """__version__ 必须来自一次函数调用，不是一个字面量。

    用 AST 而不是 grep 源码文本：注释里出现「setuptools_scm」或者
    一个叫 0.0.0+unknown 的哨兵值，都不该被当成写死版本号。
    对着文本做断言，抓到的往往是注释。
    """
    import ast

    literals, calls = [], 0
    for node in ast.walk(init_ast()):
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "__version__"
                for t in node.targets):
            if isinstance(node.value, ast.Constant):
                literals.append(node.value.value)
            elif isinstance(node.value, ast.Call):
                calls += 1

    assert calls >= 1, "__version__ 不是从函数调用得到的（应当读包元数据）"
    # 唯一允许的字面量是「拿不到元数据」的哨兵，而且它必须一眼是假的
    assert literals == ["0.0.0+unknown"], \
        f"__init__.py 里有写死的版本号：{literals}"


def test_version_comes_from_package_metadata():
    import importlib.metadata as m
    assert tg_attest.__version__ == m.version("tg-attest")


def test_version_is_a_valid_pep440_string():
    assert re.match(r"^\d+\.\d+\.\d+", tg_attest.__version__), tg_attest.__version__
    assert tg_attest.__version__ != "0.0.0+unknown", \
        "拿不到包元数据——包没装好，或者 setuptools-scm 没生效"


def test_version_reading_needs_no_third_party_import():
    """读版本号不能把零依赖承诺作废掉。

    importlib.metadata 是标准库；setuptools_scm / pkg_resources /
    importlib_metadata（backport）都不是，出现任何一个都会让
    `pip install tg-attest` 之后 import 直接失败。
    同样走 AST——注释里提 setuptools_scm 是完全正常的。
    """
    import ast
    import sys as _sys

    stdlib = set(_sys.stdlib_module_names)
    for node in ast.walk(init_ast()):
        if isinstance(node, ast.Import):
            names = [a.name.split(".")[0] for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level:                       # 包内相对 import
                continue
            names = [(node.module or "").split(".")[0]]
        else:
            continue
        for n in names:
            assert n in stdlib, f"__init__.py 引入了非标准库依赖：{n}"


# --- 与 git tag 一致 ------------------------------------------------------

def test_version_matches_the_git_tag_when_head_is_a_clean_tag():
    """HEAD 正好在 tag 上且工作树干净时，装出来的版本必须等于那个 tag。

    工作树脏或不在 tag 上时跳过——那种状态下版本号本来就该是
    0.1.1.dev0+g<sha>，和任何 tag 都不该相等。
    """
    code, _ = git("rev-parse", "--git-dir")
    if code != 0:
        pytest.skip("不在 git 仓库里（例如从 sdist 解出来跑）")

    code, tag = git("describe", "--tags", "--exact-match")
    if code != 0:
        pytest.skip("HEAD 不在任何 tag 上")

    _, dirty = git("status", "--porcelain")
    if dirty:
        pytest.skip("工作树有未提交改动，版本号本就该带 dev 后缀")

    assert tag.startswith("v"), f"tag 应当是 vX.Y.Z 形式：{tag}"
    assert tg_attest.__version__ == tag[1:], \
        f"装出来的版本 {tg_attest.__version__} 和 tag {tag} 对不上"


def test_dev_versions_are_visibly_not_releases():
    """不在 tag 上时版本号必须一眼看出不是发布版。
    一个装了开发快照却报 0.1.0 的包，在合规场景里是能出事的。"""
    code, _ = git("describe", "--tags", "--exact-match")
    _, dirty = git("status", "--porcelain")
    if code == 0 and not dirty:
        pytest.skip("HEAD 就在 tag 上，本用例针对的是另一种情形")
    assert not is_clean_release(tg_attest.__version__), \
        f"非发布状态却报了一个干净的版本号：{tg_attest.__version__}"


# --- 与 CHANGELOG 一致 ----------------------------------------------------

def changelog_versions() -> list[str]:
    return re.findall(r"^## \[(\d+\.\d+\.\d+)\]", CHANGELOG.read_text(encoding="utf-8"),
                      re.MULTILINE)


def test_changelog_has_an_unreleased_section():
    """没有 Unreleased 小节的话，下一次改动没地方记，
    发布时就会临时补，临时补的东西不会准。"""
    assert re.search(r"^## \[Unreleased\]", CHANGELOG.read_text(encoding="utf-8"),
                     re.MULTILINE), "CHANGELOG 缺少 [Unreleased] 小节"


def test_changelog_has_a_section_for_the_current_release():
    """发布版本必须在 CHANGELOG 里有对应小节。

    release.yml 会从这一节抽内容做 GitHub Release，抽不到就等于
    发了一个没有说明的版本。
    """
    v = tg_attest.__version__
    if not is_clean_release(v):
        pytest.skip(f"{v} 是开发版，对应小节还在 Unreleased 里")
    assert v in changelog_versions(), f"CHANGELOG 里没有 {v} 的小节"


def test_every_git_tag_has_a_changelog_section():
    """反过来也要成立：打过的 tag 都得能在 CHANGELOG 里找到。"""
    code, out = git("tag", "-l", "v*")
    if code != 0 or not out:
        pytest.skip("还没有 tag")
    versions = changelog_versions()
    for tag in out.splitlines():
        assert tag[1:] in versions, f"tag {tag} 在 CHANGELOG 里没有对应小节"


def test_changelog_versions_are_unique_and_descending():
    versions = changelog_versions()
    assert len(set(versions)) == len(versions), "CHANGELOG 里有重复的版本小节"
    as_tuples = [tuple(int(x) for x in v.split(".")) for v in versions]
    assert as_tuples == sorted(as_tuples, reverse=True), \
        "CHANGELOG 的版本小节应当从新到旧排列"


def test_changelog_section_for_current_version_is_not_empty():
    """能抽到但内容是空的，等于发了个空说明。"""
    v = tg_attest.__version__
    if not is_clean_release(v):
        pytest.skip("开发版")
    body = extract_changelog_section(v)
    assert body and len(body.strip()) > 80, f"{v} 的 CHANGELOG 小节太短或为空"


def extract_changelog_section(version: str) -> str:
    """抽出某个版本的小节内容。release.yml 用的是同一套规则。"""
    text = CHANGELOG.read_text(encoding="utf-8")
    m = re.search(rf"^## \[{re.escape(version)}\].*?$(.*?)(?=^## \[|\Z)",
                  text, re.MULTILINE | re.DOTALL)
    return m.group(1).strip() if m else ""


def test_changelog_extraction_matches_what_the_workflow_does():
    """抽取逻辑在 release.yml 里也有一份。正则必须逐字相同，
    否则 GitHub Release 的内容和这里断言的不是同一段。"""
    wf = ROOT / ".github" / "workflows" / "release.yml"
    if not wf.is_file():
        pytest.skip("发布包里不含 .github/，这条只在仓库内有意义")

    script = wf.read_text(encoding="utf-8")
    pattern = r'rf"^## \[{re.escape(version)}\].*?$(.*?)(?=^## \[|\Z)"'
    assert pattern in script, \
        "release.yml 里的 CHANGELOG 抽取正则和 tests/test_version.py 的对不上"
