"""tg-attest 端到端演示：决策 → 封存 → 外部锚定 → 篡改检测 → 选择性披露。

跑这个文件会真实调用 freetsa.org 取一个合格时间戳。
"""

from dataclasses import asdict
import json

from record import Ledger, EvidenceRef, GateVerdict, DecisionRecord, EpochSeal
from anchor import AnchorQueue

led = Ledger()
queue = AnchorQueue()

# --- 1. 三条被记录的决策 ------------------------------------------------------
print("【1】写入决策")
for tic, eps, act in [("AAPL", "1.5300", "BUY"),
                      ("MSFT", "2.9400", "BUY"),
                      ("NVDA", "0.8100", "HOLD")]:
    r = led.append(
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
    )
    print(f"  seq={r.seq} {tic:5} {act:4} record_hash={r.record_hash[:12]}…")

# --- 2. 封存 + 外部锚定 -------------------------------------------------------
print("\n【2】封存 epoch 并向 TSA 锚定")
seal = led.seal_epoch()
print(f"  merkle_root = {seal.merkle_root[:24]}…")
queue.enqueue(seal.epoch_id, seal.epoch_hash())
anchor = queue.flush(timeout=15)

if anchor and anchor.ok:
    anchor.write_token("epoch_000.tsr")
    # 把 token 回写进封存记录
    led._epochs[0] = EpochSeal(**{**asdict(seal), "tsa_token": anchor.token_b64})
    print(f"  token {len(anchor.token_bytes())} 字节 → epoch_000.tsr")
    print("  审计方可直接执行（无需安装 tg-attest）：")
    print(f"    openssl ts -reply -in epoch_000.tsr -token_in -text")
else:
    print(f"  锚定失败，已留在队列等下轮：{anchor.error if anchor else 'no tsa'}")

# --- 3. 向审计选择性披露 ------------------------------------------------------
print("\n【3】只出示 seq=0 这一条，不暴露另外两条")
bundle = led.disclose(0)
print(f"  bundle 体积 = {len(json.dumps(bundle, default=str))} 字节，"
      f"证明路径 {len(bundle['proof'])} 层")
print(f"  第三方独立校验 = {Ledger.verify_disclosure(bundle)}")
print("  bundle 内含 seq=0 的完整内容 + 包含证明 + epoch 根；")
print("  另外两条决策的内容与哈希均未出现在其中。")

# --- 4. 篡改检测 --------------------------------------------------------------
print("\n【4】把 NVDA 的 HOLD 改成 BUY，并顺手重算 record_hash")
from record import hash_obj
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



# --- 5. 导出自包含披露包并离线验证 -------------------------------------------
print("\n【5】导出披露包，交给审计方独立验证")
from verify import export_bundle
led2 = Ledger()
for tic, eps, act in [("AAPL", "1.5300", "BUY"), ("MSFT", "2.9400", "BUY"),
                      ("NVDA", "0.8100", "HOLD")]:
    led2.append(actor={"type": "agent", "id": "alpha-v2/pead"},
                model={"provider": "anthropic", "id": "claude-opus-5",
                       "version": "2026-06", "params_hash": "cfg-a1b2"},
                inputs={"question": f"{tic} 财报后仓位决策"},
                output={"action": act, "size_bps": 40},
                evidence=[EvidenceRef.of(f"fmp:earnings:{tic}:FY2026Q1",
                                         {"epsActual": eps},
                                         as_of="2026-05-02T20:00:00+00:00")],
                gates=[GateVerdict("evidence_gate", "pass",
                                   {"lookahead_violations": 0})],
                labels={"ticker": tic})
s2 = led2.seal_epoch()
q2 = AnchorQueue(); q2.enqueue(s2.epoch_id, s2.epoch_hash())
a2 = q2.flush(timeout=15)
if a2 and a2.ok:
    led2._epochs[0] = EpochSeal(**{**asdict(s2), "tsa_token": a2.token_b64})
    path = export_bundle(led2, 0, "decision_0000.json")
    import os
    print(f"  {path} — {os.path.getsize(path)} 字节，自包含")
    print("  审计方执行：python3 tg_verify.py decision_0000.json --ca <自行取得>")
