"""真实调用外部 TSA 的测试。默认 deselect，CI 的 nightly job 单独跑。

为什么要和其余测试分开：这些用例的成败取决于别人家服务器今天在不在，
混在主测试套里会让 CI 变成一个「有时候红」的东西，而一个有时候红的 CI
等于没有 CI——人会开始习惯性忽略红灯。

为什么还是要跑：build_tsq 与 openssl 逐字节一致只证明我们的请求格式对，
不证明真实 TSA 会接受它、返回的东西我们解析得了、签出来的 token 我们验得过。
那是另一件事，只能真打一次才知道。
"""

from __future__ import annotations

import base64

import pytest

from helpers import make_ledger
from tg_attest.anchor import DEFAULT_TSAS, AnchorQueue, anchor_hash
from tg_attest.record import EpochSeal
from tg_attest.verify import verify_token

pytestmark = pytest.mark.network

TIMEOUT = 20.0


@pytest.mark.parametrize("tsa_url", DEFAULT_TSAS)
def test_real_tsa_round_trip(tsa_url):
    """对每一家 TSA 走一遍完整往返：封存 → 提交 → 取回 → 解析。

    这三家都不是 eIDAS QTSP，只适合开发和内部完整性用途。
    真要走 Article 12 的合规叙事，必须换成 EU 可信列表上的 QTSP。
    """
    led = make_ledger()
    seal = led.seal_epoch()
    ehash = seal.epoch_hash()

    a = anchor_hash(ehash, tsa_url, timeout=TIMEOUT, epoch_id=seal.epoch_id)
    if not a.ok:
        pytest.skip(f"{tsa_url} 当前不可用：{a.error or a.status}")

    assert a.status in ("granted", "grantedWithMods")
    assert a.anchored_hash == ehash
    assert len(a.token_bytes()) > 500

    # 回写 token 之后，epoch_hash 必须一字不变——否则刚盖的戳当场作废
    led._epochs[0] = EpochSeal(**{**seal.__dict__, "tsa_token": a.token_b64})
    assert led._epochs[0].epoch_hash() == ehash
    assert led.verify() == []


@pytest.mark.parametrize("tsa_url", DEFAULT_TSAS)
def test_returned_token_actually_stamps_our_hash(tsa_url):
    """写入路径不检查返回的 token 盖的是不是我们提交的那个哈希——
    它只存不验。所以这条断言在这里补上：真实 TSA 返回的 token，
    其 messageImprint 必须等于我们提交的 epoch_hash。

    这也顺带说明为什么写入路径存下来的东西必须尽早验一次：
    一个坏掉的（或被中间人替换的）token 在写入时看不出来，
    要等到几个月后审计才暴露，那时已经补不回来了。
    见 docs/threat-model.md「写入时不验证」一节。
    """
    led = make_ledger()
    ehash = led.seal_epoch().epoch_hash()

    a = anchor_hash(ehash, tsa_url, timeout=TIMEOUT)
    if not a.ok:
        pytest.skip(f"{tsa_url} 当前不可用：{a.error or a.status}")

    r = verify_token(a.token_bytes(), ehash, None)
    assert r.checks["messageImprint 匹配 epoch_hash"] is True
    assert r.checks["TSA 签名有效"] is True
    assert r.checks["EKU 仅含 timeStamping"] is True
    assert r.gen_time
    # 没给 ca_bundle，所以整体仍然不算通过——这是刻意的
    assert r.ok is False


def test_anchor_queue_falls_back_across_providers():
    """一家挂了就换下一家。TSA 不可用绝不能阻塞生产决策路径。"""
    q = AnchorQueue(("http://127.0.0.1:9/nope",) + DEFAULT_TSAS)
    led = make_ledger()
    seal = led.seal_epoch()
    q.enqueue(seal.epoch_id, seal.epoch_hash())

    a = q.flush(timeout=TIMEOUT)
    if a is None:
        pytest.skip("所有 TSA 当前都不可用")
    assert a.ok
    assert q.pending == [], "锚定成功后队列应当清空"
    assert q.anchors[0].status == "error", "第一家应当失败并被记录下来"


def test_unreachable_tsa_does_not_raise():
    """失败必须降级成一个带 error 的 Anchor，不能抛异常——
    异常会顺着调用栈冲进生产决策路径。"""
    a = anchor_hash("ab" * 32, "http://127.0.0.1:9/nope", timeout=2.0)
    assert a.ok is False
    assert a.status == "error"
    assert a.error
    assert a.token_b64 is None


def test_token_written_to_disk_is_a_valid_tsr(tmp_path):
    """产出物必须是标准 .tsr。审计方用 openssl 就能验，不需要安装本库——
    证据的可信度不能依赖于对方信任你的库。"""
    led = make_ledger()
    ehash = led.seal_epoch().epoch_hash()

    a = None
    for url in DEFAULT_TSAS:
        a = anchor_hash(ehash, url, timeout=TIMEOUT)
        if a.ok:
            break
    if a is None or not a.ok:
        pytest.skip("所有 TSA 当前都不可用")

    p = tmp_path / "epoch_000.tsr"
    a.write_token(str(p))
    raw = p.read_bytes()
    assert raw == base64.b64decode(a.token_b64)
    assert raw[0] == 0x30

    import shutil
    import subprocess
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("环境里没有 openssl")
    out = subprocess.run([openssl, "ts", "-reply", "-in", str(p), "-token_in", "-text"],
                         capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert "Hash Algorithm: sha256" in out.stdout
    # openssl 把 messageImprint 打成十六进制转储，得按列解析出来
    assert _message_data(out.stdout) == ehash


def _message_data(text: str) -> str:
    """从 `openssl ts -reply -text` 的输出里抠出 Message data 的十六进制。

        Message data:
            0000 - a1 5c 08 91 57 90 66 4a-16 a5 89 32 0e 22 ac 05   .\\..W.fJ...
    """
    import re
    block = text.split("Message data:", 1)[1]
    out = []
    for line in block.splitlines()[1:]:
        m = re.match(r"\s+[0-9a-f]{4} - ((?:[0-9a-f]{2}[ -]){1,16})", line)
        if not m:
            break
        out.append(re.sub(r"[^0-9a-f]", "", m.group(1)))
    return "".join(out)
