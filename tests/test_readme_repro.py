"""不变量：README 里那两条 30 秒复现命令，真的能跑通。

这个项目卖的是可核验。README 里贴一条跑不通的复现命令，比不贴还糟——
第一个照着敲的人就是最想相信你的那个人。

所以这里把 README 里的命令**从 README 里读出来**执行，而不是复制一份
到测试里。复制一份的话，改了 README 忘了改测试，测试照样绿。
"""

from __future__ import annotations

import json
import re
import subprocess
import sys

import pytest

from helpers import FIXTURES
from tg_attest.record import EpochSeal

ROOT = FIXTURES.parent
VERIFY_ME = ROOT / "examples" / "verify-me"
README = (ROOT / "README.md").read_text(encoding="utf-8")


def test_the_repro_directory_ships_what_the_commands_need():
    for name in ("decision_0000.json", "freetsa_ca.pem", "epoch_000.tsr"):
        assert (VERIFY_ME / name).is_file(), f"examples/verify-me/{name} 不在仓库里"


def test_shipped_bundle_matches_the_fixture():
    """examples/ 里那份和 fixtures/ 里那份必须是同一个包，
    否则测试验的和读者验的不是一个东西。"""
    a = json.loads((VERIFY_ME / "decision_0000.json").read_text(encoding="utf-8"))
    b = json.loads((FIXTURES / "decision_0000.json").read_text(encoding="utf-8"))
    assert a == b
    assert (VERIFY_ME / "freetsa_ca.pem").read_bytes() == \
        (FIXTURES / "freetsa_ca.pem").read_bytes()


def test_shipped_tsr_is_the_bundles_token():
    import base64
    b = json.loads((VERIFY_ME / "decision_0000.json").read_text(encoding="utf-8"))
    assert (VERIFY_ME / "epoch_000.tsr").read_bytes() == base64.b64decode(b["tsa_token"])


def test_the_digest_in_the_readme_is_the_bundles_epoch_hash():
    """README 里那串十六进制必须真的是这个包的 epoch_hash。
    写错一个字符，读者的 openssl 就会报 Verification failure，
    而他会认为是这个库有问题——他没有错。
    """
    m = re.search(r"-digest ([0-9a-f]{64})", README)
    assert m, "README 里找不到 -digest <hash>"
    b = json.loads((VERIFY_ME / "decision_0000.json").read_text(encoding="utf-8"))
    expected = EpochSeal(**{**b["epoch"], "tsa_token": None}).epoch_hash()
    assert m.group(1) == expected, "README 里的 digest 和包里的 epoch_hash 对不上"


def test_openssl_route_actually_verifies(openssl):
    """路线 A：不装本库，只用 openssl。逐字执行 README 里的那条命令。"""
    m = re.search(r"-digest ([0-9a-f]{64})", README)
    r = subprocess.run(
        [openssl, "ts", "-verify", "-digest", m.group(1),
         "-in", "epoch_000.tsr", "-token_in", "-CAfile", "freetsa_ca.pem"],
        cwd=VERIFY_ME, capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "Verification: OK" in r.stdout + r.stderr


def test_openssl_route_fails_on_the_wrong_digest(openssl):
    """对照组。没有这条，上面那条可能只是因为 openssl 根本没在检查。"""
    r = subprocess.run(
        [openssl, "ts", "-verify", "-digest", "ab" * 32,
         "-in", "epoch_000.tsr", "-token_in", "-CAfile", "freetsa_ca.pem"],
        cwd=VERIFY_ME, capture_output=True, text=True)
    assert r.returncode != 0
    assert "OK" not in r.stdout


def test_cli_route_actually_verifies():
    """路线 B：装了本库的完整链条。"""
    r = subprocess.run(
        [sys.executable, "-m", "tg_attest.cli", "decision_0000.json",
         "--ca", "freetsa_ca.pem"],
        cwd=VERIFY_ME, capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "通过" in r.stdout


def test_readme_transcript_matches_actual_output():
    """README 里贴的那段输出，必须和现在真的跑出来的一致。

    只比对判定行和十个勾——时间戳那两行含 TSA 主体名，太长且会随
    证书轮换而变，钉死它只会制造无意义的失败。
    """
    r = subprocess.run(
        [sys.executable, "-m", "tg_attest.cli", "decision_0000.json",
         "--ca", "freetsa_ca.pem"],
        cwd=VERIFY_ME, capture_output=True, text=True)
    actual = [x for x in r.stdout.splitlines() if x.startswith(("  ✓", "通过"))]
    quoted = [x for x in README.splitlines() if x.startswith(("  ✓", "通过"))]
    assert actual == quoted, "README 里的输出和实际输出对不上"


def test_readme_shows_every_required_check():
    from tg_attest.verify import BUNDLE_REQUIRED_CHECKS
    for name in BUNDLE_REQUIRED_CHECKS:
        assert f"  ✓ {name}" in README, f"README 的示例输出里少了：{name}"


def test_breaking_the_bundle_fails_as_the_readme_says(tmp_path):
    """README 说：改一个字符再跑，会看到 ✗ 记录内容哈希自洽 和退出码 1。
    照做一遍。"""
    b = json.loads((VERIFY_ME / "decision_0000.json").read_text(encoding="utf-8"))
    h = b["record"]["output_hash"]
    b["record"]["output_hash"] = ("b" if h[0] != "b" else "c") + h[1:]
    p = tmp_path / "decision_0000.json"
    p.write_text(json.dumps(b, ensure_ascii=False), encoding="utf-8")

    r = subprocess.run(
        [sys.executable, "-m", "tg_attest.cli", str(p),
         "--ca", str(VERIFY_ME / "freetsa_ca.pem")],
        capture_output=True, text=True)
    assert r.returncode == 1
    assert "✗ 记录内容哈希自洽" in r.stdout


def test_readme_does_not_claim_the_shipped_ca_is_a_trust_root():
    """包内自带 CA 会让证明退化成同义反复。README 必须说清楚
    这份 CA 只是为了让复现能离线跑，真用的时候要自己取。"""
    assert "you fetch the root yourself" in README
    assert "contains no certificates" in README


@pytest.mark.parametrize("path", ["examples/verify-me/decision_0000.json",
                                  "examples/verify-me/freetsa_ca.pem"])
def test_repro_files_are_not_gitignored(path):
    """.gitignore 里有 *.tsr，别把复现文件挡在仓库外面。"""
    r = subprocess.run(["git", "check-ignore", path], cwd=ROOT,
                       capture_output=True, text=True)
    assert r.returncode != 0, f"{path} 被 .gitignore 挡住了"


def test_repro_tsr_is_not_gitignored():
    r = subprocess.run(["git", "check-ignore", "examples/verify-me/epoch_000.tsr"],
                       cwd=ROOT, capture_output=True, text=True)
    assert r.returncode != 0, "epoch_000.tsr 被 *.tsr 规则挡住了，需要 ! 例外"


def test_no_private_key_material_shipped():
    """复现目录里只能有公开材料。"""
    for f in VERIFY_ME.iterdir():
        text = f.read_bytes()
        assert b"PRIVATE KEY" not in text, f"{f.name} 里有私钥"


def test_readme_repro_is_reachable_from_the_top(monkeypatch):
    """复现那一节要在 README 靠前的位置——放在最后没人会看到。"""
    idx = README.index("## Verify it yourself")
    assert idx < len(README) * 0.5, "复现小节太靠后了"
