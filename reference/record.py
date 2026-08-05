"""
tg-attest: 面向 AI 辅助决策的防篡改决策记录层。

设计约束（与 TraceGuard 主干共享哲学，但服务不同市场）：
  1. 默认只存哈希，不存内容。合规要求可追溯，不要求你保管原文。
  2. 证据的时点绑定是一等公民：as_of（值在数据源中的有效时点）与
     observed_at（我方首次观测到该值的时刻）必须分开记录。这两者的差
     就是 TraceGuard 一直在处理的 point-in-time 问题。
  3. 审计层自身不能是黑箱。这里没有 LLM、没有启发式、没有概率。
     全部是确定性的哈希运算，任何人拿到记录都能独立复算。
  4. 零外部依赖。合规软件被采购时会审依赖树，依赖越少越好过。

对外只需要三个入口：Ledger.append() / Ledger.verify() / Ledger.seal_epoch()
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Iterable

SCHEMA = "tg-attest/1"
GENESIS = "0" * 64


# --------------------------------------------------------------------------
# 规范化序列化
# --------------------------------------------------------------------------
# 哈希链实现最常见的失败点不是密码学，是序列化不确定。同一个对象在两台机器
# 上序列化出不同字节，哈希就对不上，整条链在审计时全线报废。
#
# 规则（RFC 8785 的一个严格子集）：
#   - key 按 Unicode 码点排序
#   - 无多余空白
#   - UTF-8，不转义非 ASCII
#   - 禁止 float。IEEE754 的文本表示跨语言不一致，金额和指标一律用
#     字符串（"12.3400"）或整数最小单位。这条是硬性拒绝，不是警告。

def _reject_floats(obj: Any, path: str = "$") -> None:
    if isinstance(obj, float):
        raise TypeError(
            f"canonical json 禁止 float（位置 {path}）。"
            f"请改用字符串保留精度，或整数最小单位。"
        )
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise TypeError(f"canonical json 的 key 必须是字符串（位置 {path}）")
            _reject_floats(v, f"{path}.{k}")
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            _reject_floats(v, f"{path}[{i}]")


def canonical_bytes(obj: Any) -> bytes:
    _reject_floats(obj)
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def h(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_obj(obj: Any) -> str:
    return h(canonical_bytes(obj))


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


# --------------------------------------------------------------------------
# 记录组成部分
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class EvidenceRef:
    """一条被决策使用的证据。tg-attest 与纯观测型工具的分水岭在这里。

    Langfuse / LangSmith 之流记录的是「检索到了文档 X」。
    这里记录的是「X 在 as_of 时刻的值，其哈希是 value_hash」——
    于是日后 X 被修订时，可以证明当时的判断在当时是成立的。
    """
    source_id: str            # 逻辑数据源，如 "fmp:income-statement:AAPL:FY2025Q2"
    as_of: str                # 该值在数据源语义下的有效时点（ISO8601）
    observed_at: str          # 我方首次观测到该值的时刻（first-seen）
    value_hash: str           # 值的规范化哈希
    revision: str | None = None    # 数据源自报的版本/修订号（若有）
    value_ref: str | None = None   # 可选：外部对象存储指针，不在记录里存内容

    @staticmethod
    def of(source_id: str, value: Any, as_of: str,
           observed_at: str | None = None, **kw) -> "EvidenceRef":
        return EvidenceRef(
            source_id=source_id,
            as_of=as_of,
            observed_at=observed_at or now_iso(),
            value_hash=hash_obj(value),
            **kw,
        )


@dataclass(frozen=True)
class GateVerdict:
    """EvidenceGate 等前置闸门的判定结果。不重新实现闸门逻辑，只固化结论。"""
    gate: str
    verdict: str                      # "pass" | "fail" | "warn"
    detail: dict = field(default_factory=dict)


@dataclass(frozen=True)
class DecisionRecord:
    seq: int
    prev_hash: str
    decided_at: str
    actor: dict                       # {"type": "agent"|"human", "id": "..."}
    model: dict                       # {"provider","id","version","params_hash"}
    inputs_hash: str
    output_hash: str
    evidence: list[EvidenceRef] = field(default_factory=list)
    gates: list[GateVerdict] = field(default_factory=list)
    labels: dict = field(default_factory=dict)
    output_ref: str | None = None
    schema: str = SCHEMA
    record_hash: str = ""             # 由 body 计算，不参与自身计算

    def body(self) -> dict:
        d = asdict(self)
        d.pop("record_hash")
        return d

    def compute_hash(self) -> str:
        return hash_obj(self.body())


# --------------------------------------------------------------------------
# Merkle（RFC 6962 风格）
# --------------------------------------------------------------------------
# 为什么不用纯哈希链就够了：纯链要证明「第 47 条记录没被改过」，必须把整条链
# 交出去。监管只想看一条决策，你却暴露了全部历史。Merkle 的包含证明是
# O(log n)，可以只出示单条 + 证明路径。这是合规场景里的刚需，不是镀金。
#
# 叶子/内部节点用不同前缀做域分离，避免 CVE-2012-2459 那类二义性攻击。

def _leaf(x: str) -> str:
    return h(b"\x00" + bytes.fromhex(x))


def _node(l: str, r: str) -> str:
    return h(b"\x01" + bytes.fromhex(l) + bytes.fromhex(r))


def merkle_root(hashes: list[str]) -> str:
    if not hashes:
        return GENESIS
    level = [_leaf(x) for x in hashes]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(_node(level[i], level[i + 1]))
        if len(level) % 2:          # 奇数个：末节点直接上提，不复制
            nxt.append(level[-1])
        level = nxt
    return level[0]


def inclusion_proof(hashes: list[str], index: int) -> list[tuple[str, str]]:
    """返回 [(side, sibling_hash)]，side 指兄弟节点在左还是在右。"""
    if not 0 <= index < len(hashes):
        raise IndexError(index)
    level = [_leaf(x) for x in hashes]
    proof: list[tuple[str, str]] = []
    idx = index
    while len(level) > 1:
        pairs = len(level) // 2                  # 成对参与合并的对数
        promoted = len(level) % 2 == 1           # 末节点是否被直接上提
        if promoted and idx == len(level) - 1:
            idx = pairs                          # 上提：本层无兄弟，位置即 pairs
        elif idx % 2 == 0:
            proof.append(("R", level[idx + 1]))
            idx //= 2
        else:
            proof.append(("L", level[idx - 1]))
            idx //= 2
        nxt = [_node(level[i], level[i + 1]) for i in range(0, pairs * 2, 2)]
        if promoted:
            nxt.append(level[-1])
        level = nxt
    return proof


def verify_inclusion(record_hash: str, proof: list[tuple[str, str]], root: str) -> bool:
    cur = _leaf(record_hash)
    for side, sib in proof:
        cur = _node(sib, cur) if side == "L" else _node(cur, sib)
    return cur == root


@dataclass(frozen=True)
class EpochSeal:
    """一个封存周期。epoch 根之间再串成链，形成两级结构。"""
    epoch_id: int
    start_seq: int
    end_seq: int
    merkle_root: str
    prev_epoch_hash: str
    sealed_at: str
    tsa_token: str | None = None      # RFC 3161 时间戳，锚定成功后回写

    def epoch_hash(self) -> str:
        """必须排除 tsa_token——它是锚定的*结果*，不能参与被锚定的*输入*，
        否则回写 token 会改变哈希，令刚取回的时间戳立即失效。
        同理 record_hash 也不参与自身计算。这类自指是哈希链最隐蔽的一类 bug。"""
        d = asdict(self)
        d.pop("tsa_token")
        return hash_obj(d)


# --------------------------------------------------------------------------
# 账本
# --------------------------------------------------------------------------

class TamperDetected(Exception):
    pass


class Ledger:
    """仅追加的决策账本。生产环境应把 _records/_epochs 换成
    append-only 存储（S3 Object Lock / WORM 卷 / 只有 INSERT 权限的表）。
    内存实现只是为了让参考实现零依赖可跑。"""

    def __init__(self) -> None:
        self._records: list[DecisionRecord] = []
        self._epochs: list[EpochSeal] = []

    # ---- 写入 ----
    def append(self, *, actor: dict, model: dict, inputs: Any, output: Any,
               evidence: Iterable[EvidenceRef] = (),
               gates: Iterable[GateVerdict] = (),
               labels: dict | None = None,
               output_ref: str | None = None,
               decided_at: str | None = None) -> DecisionRecord:
        prev = self._records[-1].record_hash if self._records else GENESIS
        rec = DecisionRecord(
            seq=len(self._records),
            prev_hash=prev,
            decided_at=decided_at or now_iso(),
            actor=actor,
            model=model,
            inputs_hash=hash_obj(inputs),
            output_hash=hash_obj(output),
            evidence=list(evidence),
            gates=list(gates),
            labels=labels or {},
            output_ref=output_ref,
        )
        rec = DecisionRecord(**{**asdict(rec), "record_hash": rec.compute_hash(),
                                "evidence": rec.evidence, "gates": rec.gates})
        self._records.append(rec)
        return rec

    # ---- 校验 ----
    def verify(self) -> list[str]:
        """返回违规列表。空列表 = 链完整。刻意不抛异常：审计要的是
        「哪几条被动过」，不是第一条就中断。"""
        problems: list[str] = []
        prev = GENESIS
        for i, r in enumerate(self._records):
            if r.seq != i:
                problems.append(f"seq {i}: 序号错位（记录内为 {r.seq}）")
            if r.prev_hash != prev:
                problems.append(f"seq {i}: 前向链断裂")
            recomputed = r.compute_hash()
            if recomputed != r.record_hash:
                problems.append(f"seq {i}: 内容被篡改（哈希不匹配）")
            prev = r.record_hash

        prev_e = GENESIS
        for e in self._epochs:
            span = [x.record_hash for x in self._records[e.start_seq:e.end_seq + 1]]
            if merkle_root(span) != e.merkle_root:
                problems.append(f"epoch {e.epoch_id}: Merkle 根不匹配")
            if e.prev_epoch_hash != prev_e:
                problems.append(f"epoch {e.epoch_id}: 周期链断裂")
            prev_e = e.epoch_hash()
        return problems

    # ---- 封存 ----
    def seal_epoch(self) -> EpochSeal:
        start = (self._epochs[-1].end_seq + 1) if self._epochs else 0
        end = len(self._records) - 1
        if end < start:
            raise ValueError("本周期内没有新记录")
        span = [r.record_hash for r in self._records[start:end + 1]]
        seal = EpochSeal(
            epoch_id=len(self._epochs),
            start_seq=start,
            end_seq=end,
            merkle_root=merkle_root(span),
            prev_epoch_hash=self._epochs[-1].epoch_hash() if self._epochs else GENESIS,
            sealed_at=now_iso(),
        )
        self._epochs.append(seal)
        return seal

    # ---- 选择性披露 ----
    def disclose(self, seq: int) -> dict:
        """向监管/审计出示单条决策，不暴露同周期内的其他记录。"""
        epoch = next((e for e in self._epochs
                      if e.start_seq <= seq <= e.end_seq), None)
        if epoch is None:
            raise ValueError(f"seq {seq} 尚未封存，无法出具包含证明")
        span = [r.record_hash for r in self._records[epoch.start_seq:epoch.end_seq + 1]]
        rec = self._records[seq]
        return {
            "record": rec.body(),
            "record_hash": rec.record_hash,
            "proof": inclusion_proof(span, seq - epoch.start_seq),
            "epoch": asdict(epoch),
        }

    @staticmethod
    def verify_disclosure(bundle: dict) -> bool:
        """第三方独立校验，不需要账本本体。"""
        if hash_obj(bundle["record"]) != bundle["record_hash"]:
            return False
        return verify_inclusion(
            bundle["record_hash"],
            [tuple(p) for p in bundle["proof"]],
            bundle["epoch"]["merkle_root"],
        )

    # ---- 供 ReplayGate 使用 ----
    def evidence_index(self) -> dict[str, list[tuple[int, EvidenceRef]]]:
        """按 source_id 归集全部证据引用。ReplayGate 拿今天的值重算哈希，
        与此处的 value_hash 比对，即可定位所有『依据已被修订』的历史决策。"""
        idx: dict[str, list[tuple[int, EvidenceRef]]] = {}
        for r in self._records:
            for ev in r.evidence:
                idx.setdefault(ev.source_id, []).append((r.seq, ev))
        return idx


# --------------------------------------------------------------------------
# 演示
# --------------------------------------------------------------------------

if __name__ == "__main__":
    led = Ledger()

    for i, (tic, eps) in enumerate([("AAPL", "1.5300"),
                                    ("MSFT", "2.9400"),
                                    ("NVDA", "0.8100")]):
        led.append(
            actor={"type": "agent", "id": "alpha-v2/pead"},
            model={"provider": "anthropic", "id": "claude-opus-5",
                   "version": "2026-06", "params_hash": hash_obj({"temperature": "0"})},
            inputs={"question": f"{tic} 财报后是否建仓"},
            output={"action": "BUY", "size_bps": 40},
            evidence=[EvidenceRef.of(
                f"fmp:earnings:{tic}:FY2026Q1",
                {"epsActual": eps},
                as_of="2026-05-02T20:00:00+00:00",
            )],
            gates=[GateVerdict("evidence_gate", "pass", {"lookahead_violations": 0})],
            labels={"ticker": tic},
        )

    seal = led.seal_epoch()
    print(f"封存 epoch {seal.epoch_id}: seq {seal.start_seq}-{seal.end_seq}")
    print(f"  merkle_root = {seal.merkle_root[:16]}…")
    print(f"  校验结果    = {led.verify() or '完整'}\n")

    bundle = led.disclose(1)
    print(f"向审计出示 seq=1，证明路径长度 {len(bundle['proof'])}"
          f"（未暴露另外 2 条决策）")
    print(f"  第三方独立校验 = {Ledger.verify_disclosure(bundle)}\n")

    # 篡改：把 MSFT 的决策规模从 40bps 改成 400bps
    tampered = asdict(led._records[1])
    tampered["output_hash"] = hash_obj({"action": "BUY", "size_bps": 400})
    led._records[1] = DecisionRecord(**{**tampered,
                                        "evidence": led._records[1].evidence,
                                        "gates": led._records[1].gates})
    print("场景 A — 直接改内容，不动 record_hash：")
    for p in led.verify():
        print("  ✗", p)

    # 聪明的篡改者：改完内容顺手把 record_hash 也重算了
    fixed = asdict(led._records[1])
    ev, gt = led._records[1].evidence, led._records[1].gates
    fixed["record_hash"] = ""
    tmp = DecisionRecord(**{**fixed, "evidence": ev, "gates": gt})
    led._records[1] = DecisionRecord(**{**fixed, "evidence": ev, "gates": gt,
                                        "record_hash": tmp.compute_hash()})
    print("\n场景 B — 连 record_hash 一起重算（单条自校验已失效）：")
    for p in led.verify():
        print("  ✗", p)
    print("\n  ↑ 单条哈希救不了，是前向链 + 已封存的 Merkle 根兜住的。")
    print("    这也是为什么 epoch 根必须尽快外部锚定——见文件末尾 TODO。")


# --------------------------------------------------------------------------
# TODO（按优先级，这些决定它是「内部日志」还是「法庭上站得住的证据」）
# --------------------------------------------------------------------------
# 1. [关键] RFC 3161 外部时间戳锚定。
#    自己控制的哈希链对自己不构成证据——你可以整条重写。必须把 EpochSeal
#    的 epoch_hash 提交给第三方 TSA，取回 token 存进 tsa_token。eIDAS 下
#    合格时间戳具备法律推定效力，成本以分计（FreeTSA / DigiCert 均可）。
#    这一步大约半天工作量，但它是「有日志」和「有证据」的分界线。
# 2. append-only 存储后端：S3 Object Lock(COMPLIANCE 模式) / 仅 INSERT 权限的表。
#    内存 list 只是参考实现。
# 3. 保留策略：高风险系统最低 6 个月，生物识别/执法类 24 个月。
# 4. OTel 导出：复用主干已有的 dual-write，把 record_hash 作为 span attribute
#    写进现有 trace，使 tg-attest 与 Langfuse/Arize 共存而非竞争。
# 5. ReplayGate：基于 evidence_index() 实现，是差异化最强的一层，但依赖
#    本模块先跑起来积累历史快照。
