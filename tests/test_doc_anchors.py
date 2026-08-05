"""不变量：文档里每一条 `](...#anchor)` 链接都指向真实存在的标题。

锚点写错不会 404。GitHub 照样 200，只是静默滚到页首——所以只看状态码的
链接检查会把它报成健康。读者点进去落在一个看着挺像的位置，然后判断是这份
文档写得乱，而不是这条链接坏了。

这和本仓库反复栽的那类坑是同一个形状：**成功信号不等于正确信号**。参见
docs/fail-open-audit.md 里 "Hashing the representation instead of the value"
一节，以及 test_readme_repro.py 为什么坚持执行 README 里的命令而不是读一遍。

范围限于仓库内锚点，离线对磁盘上的文件校验。指向**另一个仓库**的锚点要对
那个仓库的默认分支解析，本测试套件控制不了它，而且它可能在这里没有任何
提交的情况下失效——那属于发布时检查，不是构建时检查。
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def github_slug(heading: str) -> str:
    """复刻 github-slugger，也就是 GitHub 实际生成锚点的规则。

    转小写 → 去 HTML 标签 → 删掉所有非「单词字符/空格/连字符」的字符
    （反引号、标点、强调符号都是在这一步没的）→ 空格转连字符。
    """
    s = heading.strip().lower()
    s = re.sub(r"<[!/a-z][^>]*>", "", s)
    s = re.sub(r"[^\w\- ]", "", s, flags=re.UNICODE)
    return s.replace(" ", "-")


def heading_anchors(markdown: str) -> set[str]:
    """一份文档里 GitHub 会生成的全部锚点。

    跳过围栏代码块：shell 示例里的 `#` 是注释不是标题，算进去会凭空造出
    并不存在的锚点。重复标题按 github-slugger 加 `-1`、`-2` 后缀。
    """
    found: list[str] = []
    seen: dict[str, int] = {}
    fence: str | None = None
    for line in markdown.splitlines():
        stripped = line.strip()
        if stripped.startswith(("```", "~~~")):
            token = stripped[:3]
            fence = None if fence == token else (fence or token)
            continue
        if fence is not None:
            continue
        m = re.match(r"^(#{1,6})\s+(.*?)\s*#*\s*$", line)
        if not m:
            continue
        slug = github_slug(m.group(2))
        n = seen.get(slug, 0)
        seen[slug] = n + 1
        found.append(slug if n == 0 else f"{slug}-{n}")
    return set(found)


# 从 sdist 解包出来跑的时候没有 .git，`git ls-files` 会以 128 退出。这个套件
# 必须能在解包后的 sdist 里跑（CI 有一条 job 专门验这个），所以 git 不可用时
# 退回文件系统遍历。
_WALK_SKIP = {
    ".git", ".venv", "venv", "node_modules", "build", "dist", "mutants",
    ".pytest_cache", ".ruff_cache", ".mypy_cache", "__pycache__", "htmlcov",
}


def tracked_markdown() -> list[Path]:
    try:
        out = subprocess.run(
            ["git", "ls-files", "*.md"], cwd=ROOT, capture_output=True, text=True, check=True
        )
        paths = [ROOT / line for line in out.stdout.splitlines() if line]
        if paths:
            return paths
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        pass
    return [p for p in sorted(ROOT.rglob("*.md")) if not _WALK_SKIP & set(p.relative_to(ROOT).parts)]


ANCHOR_LINK = re.compile(r"\]\(([^)\s]*)#([^)\s]+)\)")


def test_every_intra_repo_anchor_points_at_a_real_heading():
    problems: list[str] = []
    checked = 0
    for md in tracked_markdown():
        text = md.read_text(encoding="utf-8", errors="replace")
        for m in ANCHOR_LINK.finditer(text):
            target, anchor = m.group(1), m.group(2)
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            rel = md.relative_to(ROOT)
            dest = md if target == "" else (md.parent / target)
            if not dest.exists():
                problems.append(f"{rel}: 链接目标不存在：{target}")
                continue
            checked += 1
            anchors = heading_anchors(dest.read_text(encoding="utf-8", errors="replace"))
            if anchor.lower() not in anchors:
                near = sorted(a for a in anchors if a[:6] == anchor.lower()[:6])
                problems.append(
                    f"{rel}: '#{anchor}' 在 {dest.relative_to(ROOT)} 里没有对应标题"
                    + (f"（是不是想写 {near}？）" if near else "")
                )
    assert problems == [], "\n".join(problems)
    assert checked > 0, "一条锚点链接都没找到——说明提取逻辑坏了"


def test_the_checker_rejects_an_anchor_that_does_not_exist():
    """负对照。

    没有这条，上面那条在 heading_anchors 返回一切、或者提取器什么都没匹配到
    的时候，会一样地绿。
    """
    doc = "# Real Heading\n\ntext\n\n## 另一个标题\n"
    anchors = heading_anchors(doc)
    assert "real-heading" in anchors
    assert "另一个标题" in anchors
    assert "no-such-heading" not in anchors

    # 端到端：拿一份真的会发布的文档，故意指一个不存在的锚点。
    audit = (ROOT / "docs" / "fail-open-audit.md").read_text(encoding="utf-8")
    assert "hashing-the-representation-instead-of-the-value" in heading_anchors(audit)
    assert "hashing-the-representation-instead-of-the-valu" not in heading_anchors(audit)


def test_fenced_code_blocks_do_not_invent_anchors():
    """README 里的 console 示例含 `# comment` 行，不能被当成标题。"""
    doc = "# Real\n\n```console\n# not a heading\n$ echo hi\n```\n\n## Also Real\n"
    assert heading_anchors(doc) == {"real", "also-real"}


@pytest.mark.parametrize(
    ("heading", "expected"),
    [
        ("Verify it yourself, in about 30 seconds", "verify-it-yourself-in-about-30-seconds"),
        ("Hashing the representation instead of the value", "hashing-the-representation-instead-of-the-value"),
        ("`code` and **bold**", "code-and-bold"),
        ("Accepted fail-open paths", "accepted-fail-open-paths"),
    ],
)
def test_slug_matches_github(heading, expected):
    assert github_slug(heading) == expected
