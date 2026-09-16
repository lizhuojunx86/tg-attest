"""tg-attest — 面向 AI 辅助决策的防篡改记录层。

    from tg_attest import Ledger, EvidenceRef, GateVerdict

包被切成依赖画像不同的两半，这个文件的全部工作就是维持那条切线：

    写入路径 record / anchor —— 只用标准库。跑在生产决策热路径上。
    验证路径 verify         —— 需要 asn1crypto + cryptography，
                               装了 tg-attest[tsa] 才有。

所以下面三个验证侧的名字用 PEP 562 的模块级 __getattr__ 延迟导入。
如果在这里直接 `from .verify import verify_bundle`，那么零依赖环境下
连 `import tg_attest` 都会当场 ImportError——写入路径的零依赖承诺
会被一行 import 语句作废，而且是在用户的生产部署里作废。
tests/test_zero_deps.py 把这条钉死了。
"""

from __future__ import annotations

from .anchor import AnchorQueue, anchor_hash
from .eutl import CertFacts, Snapshot, Verdict  # noqa: F401
from .record import DecisionRecord, EpochSeal, EvidenceRef, GateVerdict, Ledger

# 版本号从已安装的包元数据读，唯一来源是 git tag（见 pyproject 的
# setuptools_scm）。importlib.metadata 是标准库，不违反零依赖。
# 从源码树直接跑而没装包时拿不到元数据，退回一个明显是假的值——
# 报一个看起来像真版本号的猜测，比报「未知」更糟。
try:
    from importlib.metadata import PackageNotFoundError
    from importlib.metadata import version as _pkg_version

    __version__ = _pkg_version("tg-attest")
except PackageNotFoundError:            # pragma: no cover - 未安装时才会走到
    __version__ = "0.0.0+unknown"

__all__ = [
    # 写入路径：零依赖
    "Ledger",
    "EvidenceRef",
    "GateVerdict",
    "DecisionRecord",
    "EpochSeal",
    "anchor_hash",
    "AnchorQueue",
    # EUTL 合格状态查询：零依赖，随写入路径一起立即可用
    "Snapshot",
    "Verdict",
    "CertFacts",
    # 验证路径：需要 tg-attest[tsa]，延迟导入
    "verify_token",
    "verify_bundle",
    "export_bundle",
]

_VERIFY_PATH = frozenset({"verify_token", "verify_bundle", "export_bundle"})

_MISSING = (
    "{name} 属于验证路径，需要附加依赖：pip install tg-attest[tsa]\n"
    "写入路径（Ledger / EvidenceRef / anchor_hash / AnchorQueue）不受影响，"
    "零依赖可用。\n"
    "另一条路是完全不装本库，用标准 openssl 验证："
    "openssl ts -verify -digest <epoch_hash> -in epoch.tsr -token_in -CAfile <ca>"
)


def __getattr__(name: str):
    if name in _VERIFY_PATH:
        try:
            from . import verify
        except ImportError as e:
            raise ImportError(_MISSING.format(name=name)) from e
        return getattr(verify, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(__all__)
