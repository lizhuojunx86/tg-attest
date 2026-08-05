"""共享 fixture。

fixtures/ 下那两个文件让整套验证测试完全离线，而且不会随时间过期：
证书有效期是拿 token 内被签名的 genTime 去校验的，不是拿 datetime.now()。
所以 2040 年跑这套测试，结论和今天一模一样。这既是测试策略，
也是本库对「长期可验证」这件事的实现方式——见 docs/threat-model.md。
"""

from __future__ import annotations

# --- 必须在任何 tg_attest import 之前 -------------------------------------
# 把与本目录同级的 src/ 顶到 sys.path 最前面。
#
# 为什么需要：`pip install -e .` 装的是一个 .pth 文件，内容是一行
# 绝对路径 <repo>/src，追加在 sys.path 末尾。平时无所谓，跑变异测试时
# 是致命的——mutmut 把源码复制进 mutants/ 并在那里跑 pytest，但
# `import tg_attest` 仍然顺着 .pth 找回真实的 <repo>/src，
# 变异体从来没有被加载过。结果是每一个变异体都「存活」，
# 而那份报告看起来只是「测试很弱」，不是「工具没装对」。
# 0 killed 这种数字要当成工具坏了来查，不是当成结论来读。
import sys as _sys
from pathlib import Path as _Path

_src = _Path(__file__).resolve().parent.parent / "src"
if _src.is_dir() and str(_src) not in _sys.path[:1]:
    _sys.path.insert(0, str(_src))
# --------------------------------------------------------------------------

import json
import shutil

import pytest

from helpers import FIXTURES  # noqa: E402, F401  (向上查找，见 helpers)


@pytest.fixture(scope="session")
def ca_pem() -> bytes:
    """FreeTSA 的根证书。

    注意它在测试里的角色：验证方独立获得的信任根。它放在 fixtures/ 下，
    不放在披露包里——包内自带 CA 会让整个证明退化成同义反复。
    """
    return (FIXTURES / "freetsa_ca.pem").read_bytes()


@pytest.fixture(scope="session")
def bundle_json() -> dict:
    """真实跑出来的披露包，freetsa.org 签的时间戳。"""
    return json.loads((FIXTURES / "decision_0000.json").read_text(encoding="utf-8"))


@pytest.fixture
def bundle(bundle_json: dict) -> dict:
    """每个用例拿到一份独立深拷贝，可以随便改坏。"""
    return json.loads(json.dumps(bundle_json))


@pytest.fixture(scope="session")
def openssl() -> str:
    """openssl 可执行文件路径；没有就 skip，不 fail。

    构建环境里没装 openssl 是很正常的事，不该让整个测试套变红。
    但 CI 的 lint+test job 明确装了 openssl，所以这条断言在 CI 里
    一定会真的执行——skip 只对本地开发生效。
    """
    exe = shutil.which("openssl")
    if exe is None:
        pytest.skip("环境里没有 openssl，跳过逐字节比对")
    return exe
