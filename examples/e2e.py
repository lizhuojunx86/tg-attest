"""端到端演示：决策 → 封存 → 外部锚定 → 篡改检测 → 选择性披露。

    python examples/e2e.py [输出目录]

会真实调用 TSA，需要联网。默认写到临时目录，传一个路径就写到那里。
需要验证路径的依赖：pip install -e ".[tsa]"
"""

from __future__ import annotations

import json
import sys
import tempfile
from dataclasses import asdict
from pathlib import Path

from tg_attest import (
    AnchorQueue,
    DecisionRecord,
    EvidenceRef,
    GateVerdict,
    Ledger,
    export_bundle,
)
from tg_attest.record import hash_obj

ROWS = [("AAPL", "1.5300", "BUY"), ("MSFT", "2.9400", "BUY"), ("NVDA", "0.8100", "HOLD")]


def build_ledger() -> Ledger:
    led = Ledger()
    for tic, eps, act in ROWS:
        led.append(
            actor={"type": "agent", "id": "alpha-v2/pead"},
            model={"provider": "anthropic", "id": "claude-opus-5",
                   "version": "2026-06", "params_hash": "cfg-a1b2"},
            inputs={"question": f"{tic} 财报后仓位决策"},
            output={"action": act, "size_bps": 40},
            evidence=[EvidenceRef.of(
                f"fmp:earnings:{tic}:FY2026Q1",
                {"epsActual": eps},
                as_of="2026-05-02T20:00:00+00:00",   # 值在数据源中的有效时点
            )],
            gates=[GateVerdict("evidence_gate", "pass", {"lookahead_violations": 0})],
            labels={"ticker": tic},
            # 声明严格档案：证据和闸门缺任何一个，append 直接抛异常。
            # 示例应当展示要求最高的用法，不是最省事的用法。
            profile="eu-ai-act",
        )
    return led


def main(outdir: Path) -> int:
    # --- 1. 写入决策 -------------------------------------------------------
    print("【1】写入决策")
    led = build_ledger()
    for r in led._records:
        print(f"  seq={r.seq} {r.labels['ticker']:5} "
              f"profile={r.profile} record_hash={r.record_hash[:12]}…")

    # 少传证据会被当场拒绝，而不是写进去一条哈希完美但内容为空的记录
    from tg_attest.record import ProfileViolation
    try:
        led.append(actor={"type": "agent", "id": "alpha-v2/pead"},
                   model={"provider": "anthropic", "id": "claude-opus-5",
                          "version": "2026-06", "params_hash": "cfg-a1b2"},
                   inputs={"question": "忘了传证据"}, output={"action": "BUY"},
                   profile="eu-ai-act")
    except ProfileViolation as e:
        print(f"  ✗ 少传证据被拒绝：{e}")
        print("    没有这一步，你会得到一条哈希、链、时间戳全部完美的空记录。")

    # --- 2. 封存 + 外部锚定 ------------------------------------------------
    print("\n【2】封存 epoch 并向 TSA 锚定")
    seal = led.seal_epoch()
    print(f"  merkle_root = {seal.merkle_root[:24]}…")
    print(f"  epoch_hash  = {seal.epoch_hash()[:24]}…  ← 提交给 TSA 的就是这个")

    queue = AnchorQueue()
    queue.enqueue(seal.epoch_id, seal.epoch_hash())
    anchor = queue.flush(timeout=15)

    if anchor and anchor.ok:
        tsr = outdir / "epoch_000.tsr"
        anchor.write_token(str(tsr))
        # 回写 token。用 attach_anchor 而不是直接动 _epochs：它同时把这次锚定的
        # eIDAS 合格判定排队，交给下一个 seal_epoch 写进下一个 epoch 的被哈希体
        # （issue #3）。epoch_hash 排除 tsa_token，所以这一步不会改变刚被签名的哈希——
        # 若不排除，这里就会当场作废掉刚取回的时间戳。
        led.attach_anchor(anchor)
        assert led._epochs[0].epoch_hash() == seal.epoch_hash()

        print(f"  {anchor.tsa_url} 签发，{len(anchor.token_bytes())} 字节 → {tsr.name}")
        print("  审计方可直接执行（无需安装 tg-attest）：")
        print(f"    openssl ts -reply -in {tsr.name} -token_in -text")
    else:
        print(f"  锚定失败，已留在队列等下轮：{anchor.error if anchor else 'no tsa'}")
        print("  TSA 不可用不阻塞决策路径——这是刻意的降级行为。")

    # --- 3. 选择性披露 -----------------------------------------------------
    print("\n【3】只出示 seq=0 这一条，不暴露另外两条")
    bundle = led.disclose(0)
    print(f"  bundle 体积 = {len(json.dumps(bundle, default=str))} 字节，"
          f"证明路径 {len(bundle['proof'])} 层")
    print(f"  第三方独立校验 = {Ledger.verify_disclosure(bundle)}")
    blob = json.dumps(bundle, default=str)
    assert "MSFT" not in blob and "NVDA" not in blob
    print("  另外两条决策的内容与哈希均未出现在其中。")

    # --- 4. 篡改检测 -------------------------------------------------------
    print("\n【4】把 NVDA 的 HOLD 改成 BUY，并顺手重算 record_hash")
    bad = asdict(led._records[2])
    ev, gt = led._records[2].evidence, led._records[2].gates
    bad["output_hash"] = hash_obj({"action": "BUY", "size_bps": 40})
    bad["record_hash"] = ""
    tmp = DecisionRecord(**{**bad, "evidence": ev, "gates": gt})
    led._records[2] = DecisionRecord(**{**bad, "evidence": ev, "gates": gt,
                                        "record_hash": tmp.compute_hash()})
    for p in led.verify():
        print("  ✗", p)
    print("  注意：改的是最后一条，后面没有记录，所以前向链完好无损。")
    print("  单条自校验也被绕过了。唯一抓住它的是已封存的 Merkle 根——")
    print("  而那个根已被 TSA 签名，篡改者无法重建。这就是锚定买到的东西。")

    # --- 5. 导出披露包 -----------------------------------------------------
    print("\n【5】导出自包含披露包，交给审计方独立验证")
    if not (anchor and anchor.ok):
        print("  跳过：本轮没拿到时间戳。")
        return 1

    led2 = build_ledger()          # 干净的一份，上面那份已被篡改
    s2 = led2.seal_epoch()
    q2 = AnchorQueue()
    q2.enqueue(s2.epoch_id, s2.epoch_hash())
    a2 = q2.flush(timeout=15)
    if not (a2 and a2.ok):
        print(f"  锚定失败：{a2.error if a2 else 'no tsa'}")
        return 1

    led2.attach_anchor(a2)
    path = outdir / "decision_0000.json"
    export_bundle(led2, 0, str(path))
    print(f"  {path} — {path.stat().st_size} 字节，自包含")
    print("  包内不含任何 CA 证书：信任根必须由验证方独立获得。")
    print("  审计方执行：")
    print(f"    python -m tg_attest.cli {path.name} --ca <自行取得的信任根>")
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1:
        d = Path(sys.argv[1])
        d.mkdir(parents=True, exist_ok=True)
        sys.exit(main(d))
    with tempfile.TemporaryDirectory() as tmp:
        print(f"（输出目录 {tmp}，传一个路径参数可以指定别处）\n")
        sys.exit(main(Path(tmp)))
