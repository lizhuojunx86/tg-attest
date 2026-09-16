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

import base64
import hashlib
import json
from dataclasses import asdict, dataclass, field, replace
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


# --------------------------------------------------------------------------
# 完整性档案（profile）
# --------------------------------------------------------------------------
# 本库能证明「这条记录没被改过」。它证明不了「当初就记全了」。
#
# 这两件事的差距是整个产品类别的边界，而且差距具体、可复现：集成方忘了传
# evidence，你会得到一条哈希、前向链、Merkle 根、TSA 签名全部完美的记录，
# 里面什么证据都没有。led.verify() 返回 []，验证器打印「通过」。
# 密码学在这里帮不上任何忙——它保护的是内容的不变性，不是内容的存在性。
#
# profile 把这个缺口从「不可见」变成「验证时报错」：记录自己声明遵循哪个
# 档案，档案规定必填项，档案名参与哈希因而不可事后篡改。
# 写入时不满足就抛异常——宁可写不进去，不要写进去一条骗人的记录。
#
# 注意它管不到什么：调用方本该用 eu-ai-act 却选了 minimal，本库无从判断。
# 见 docs/threat-model.md「profile 挡不住什么」。

class ProfileViolation(ValueError):
    """记录不满足它所声明的完整性档案。写入路径抛这个，不静默降级。"""


@dataclass(frozen=True)
class RecordProfile:
    """一个完整性档案。字段全是「至少要有什么」，没有「不能有什么」。"""
    name: str
    require_evidence: int = 0
    require_gates: int = 0
    evidence_fields: tuple[str, ...] = ()


PROFILES: dict[str, RecordProfile] = {
    # 最低限度：谁、用什么模型、输入和输出的哈希。少了任何一项，
    # 这条记录在审计时都回答不了「这是谁做的决定」。
    "minimal": RecordProfile("minimal"),

    # 对准 Article 12(2)(b)/(c)：必须记下依据了什么证据、以及闸门结论。
    # 每条证据的 as_of / observed_at 都要齐——这两个时点的差正是本库的存在理由，
    # 缺了它们，evidence 退化成「检索发生过」，和可观测工具就没区别了。
    "eu-ai-act": RecordProfile(
        "eu-ai-act",
        require_evidence=1,
        require_gates=1,
        evidence_fields=("source_id", "as_of", "observed_at", "value_hash"),
    ),
}

DEFAULT_PROFILE = "minimal"


def _blank(v) -> bool:
    return v is None or (isinstance(v, str) and not v.strip())


def profile_violations(body: dict) -> list[str]:
    """检查一个记录 body 是否满足它自称的 profile。返回违规列表，空表示通过。

    刻意吃 dict 而不是 DecisionRecord：验证方手里只有从 JSON 读出来的
    披露包，必须能用同一套规则离线复核，不需要重建对象。
    """
    name = body.get("profile")
    prof = PROFILES.get(name) if isinstance(name, str) else None
    if prof is None:
        # 认不出的档案名不能当成「那就按最宽松的算」。
        return [f"未知的完整性档案：{name!r}（已知：{sorted(PROFILES)}）"]

    out: list[str] = []
    actor = body.get("actor") or {}
    model = body.get("model") or {}
    if not isinstance(actor, dict) or _blank(actor.get("id")):
        out.append("actor.id 缺失")
    if not isinstance(model, dict) or _blank(model.get("id")):
        out.append("model.id 缺失")
    if _blank(body.get("inputs_hash")):
        out.append("inputs_hash 缺失")
    if _blank(body.get("output_hash")):
        out.append("output_hash 缺失")

    evidence = body.get("evidence") or []
    gates = body.get("gates") or []
    if len(evidence) < prof.require_evidence:
        out.append(f"{prof.name} 要求至少 {prof.require_evidence} 条证据，实为 {len(evidence)}")
    if len(gates) < prof.require_gates:
        out.append(f"{prof.name} 要求至少 {prof.require_gates} 道闸门，实为 {len(gates)}")

    for i, ev in enumerate(evidence):
        if not isinstance(ev, dict):
            out.append(f"evidence[{i}] 结构不对")
            continue
        for f in prof.evidence_fields:
            if _blank(ev.get(f)):
                out.append(f"evidence[{i}].{f} 缺失")
    return out


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
    # 本记录声明遵循的完整性档案。参与哈希，因而事后改不动——
    # 否则「声明了 eu-ai-act」这句话本身就可以在审计前被降级成 minimal。
    profile: str = DEFAULT_PROFILE
    record_hash: str = ""             # 由 body 计算，不参与自身计算

    def body(self) -> dict:
        d = asdict(self)
        d.pop("record_hash")
        return d

    def compute_hash(self) -> str:
        return hash_obj(self.body())

    def profile_violations(self) -> list[str]:
        return profile_violations(self.body())


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
        # 只认 "L" / "R" 两个值。原来写成 `if side == "L" else 右`，
        # 于是任何非 "L" 的东西——空串、"r"、None——都被当成右兄弟。
        # 变异测试把 "R" 改成 "XXRXX" 后整套测试仍然全绿，正是因为
        # 那个字面量从来没被真的比较过。含义不明的输入应当拒绝，不是猜。
        if side not in ("L", "R"):
            return False
        cur = _node(sib, cur) if side == "L" else _node(cur, sib)
    return cur == root


@dataclass(frozen=True)
class AnchorAttestation:
    """对**上一个** epoch 那次锚定的判定，写进本 epoch 的被哈希体。

    为什么必须挪到下一个 epoch 才能被哈希（这是 issue #3 的全部内容）：
        eIDAS 合格状态只有拿到 token 之后才算得出来——TSA 的签名证书在
        token 里面。而 epoch N 的 epoch_hash 是**被盖戳的输入**，盖完再
        往里写任何东西，刚取回的那个时间戳当场失效。tsa_token 受同一条
        约束，本项目在那上面已经踩过一次（见 0.1.0 的 CHANGELOG）。

        但 epoch 根本来就串链。把 epoch N 的判定写进 epoch N+1 的被哈希体，
        它就随 N+1 那次锚定一起被时间戳覆盖了。代价是迟一个 epoch 生效，
        以及最后一个 epoch 的判定永远悬空——见 Ledger.unbound_anchor_count()。

    anchored_hash 与 token_sha256 一起把这条判定钉死在**那一次**锚定上。
    只写 epoch_id 是不够的：判定说的是「那个 token 的签发者当时合格」，
    不指明是哪个 token，换一个 token 再声明一次同样说得通。
    """
    epoch_id: int
    anchored_hash: str                  # 被盖戳的那个 epoch_hash
    tsa_url: str
    token_sha256: str | None            # 被判定的那个 token 的摘要
    tsa_qualified: bool | None
    eutl_ref: str | None
    qualified_checked_at: str | None
    eutl_snapshot_sha256: str | None    # 判定依据的那份快照
    # 刻意不收 qualified_reason：那是给人看的说明文字，措辞会随实现变化，
    # 放进哈希等于把一句人话变成兼容性契约。


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
    # 上一个 epoch 的锚定判定。参与本 epoch 的哈希，因此受本 epoch 的
    # 时间戳保护——这正是它放在这里而不是放在被判定的那个 epoch 里的原因。
    prev_anchor_attestation: "AnchorAttestation | None" = None

    def epoch_hash(self) -> str:
        """必须排除 tsa_token——它是锚定的*结果*，不能参与被锚定的*输入*，
        否则回写 token 会改变哈希，令刚取回的时间戳立即失效。
        同理 record_hash 也不参与自身计算。这类自指是哈希链最隐蔽的一类 bug。

        prev_anchor_attestation 为 None 时**整个键不出现**，而不是出现一个
        null。这不是洁癖：verify_bundle 是拿披露包里的 epoch 字典去构造
        EpochSeal 的，字段有了默认值之后，0.1.0 时代那些不含此键的包会被
        补上一个 null，哈希随之改变，于是每一个已经发出去的披露包当场失效。
        新增字段而不惊动旧数据，只有这一种写法。
        （反过来，判定**存在**时被删掉是查得出来的：盖戳时的哈希含它，
        删掉后重算的哈希不含它，两者不等，messageImprint 对不上。）
        """
        d = asdict(self)
        d.pop("tsa_token")
        if d.get("prev_anchor_attestation") is None:
            d.pop("prev_anchor_attestation", None)
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
        # 等待被下一个 epoch 哈希覆盖的锚定判定。见 attach_anchor()。
        self._pending_attestation: AnchorAttestation | None = None

    # ---- 写入 ----
    def append(self, *, actor: dict, model: dict, inputs: Any, output: Any,
               evidence: Iterable[EvidenceRef] = (),
               gates: Iterable[GateVerdict] = (),
               labels: dict | None = None,
               output_ref: str | None = None,
               decided_at: str | None = None,
               profile: str = DEFAULT_PROFILE) -> DecisionRecord:
        """追加一条决策记录。

        不满足 profile 就抛 ProfileViolation，什么也不写入。fail-closed 是
        刻意的：一条缺了证据的记录，一旦落进链里就会被后续每一层
        （前向链、Merkle、TSA）盖上完美的印章，此后再也分辨不出它是空的。
        写不进去是能修的问题；写进去一条骗人的记录不是。
        """
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
            profile=profile,
        )
        violations = rec.profile_violations()
        if violations:
            raise ProfileViolation(
                f"记录不满足档案 {profile!r}：" + "；".join(violations))

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
        expect_start = 0
        for e in self._epochs:
            # epoch 之间必须首尾相接。留缝意味着那一段记录没有被任何
            # Merkle 根覆盖，也就没有被任何时间戳锚定——它们可以被
            # 连着 record_hash 一起重建而查不出来（见 verify() 上面那段
            # 前向链逻辑：重建整条尾部后链是自洽的）。
            # 缝隙不会通过 seal_epoch 产生，但会通过直接改 _epochs 产生，
            # 而这正是 A3（有存储写权限的内部人）最省事的一招。
            if e.start_seq != expect_start:
                problems.append(
                    f"epoch {e.epoch_id}: 覆盖区间不连续"
                    f"（应从 seq {expect_start} 起，实为 {e.start_seq}）")
            if e.end_seq < e.start_seq:
                problems.append(f"epoch {e.epoch_id}: 区间为空或倒置")
            if e.end_seq >= len(self._records):
                problems.append(
                    f"epoch {e.epoch_id}: 覆盖到不存在的记录"
                    f"（end_seq={e.end_seq}，账本只有 {len(self._records)} 条）")

            span = [x.record_hash for x in self._records[e.start_seq:e.end_seq + 1]]
            if merkle_root(span) != e.merkle_root:
                problems.append(f"epoch {e.epoch_id}: Merkle 根不匹配")
            if e.prev_epoch_hash != prev_e:
                problems.append(f"epoch {e.epoch_id}: 周期链断裂")

            # 锚定判定必须确实说的是上一个 epoch 的那次锚定。
            # 不校验的话，这段结构就只是"一段被哈希保护的自由文本"——
            # 保证了它没被改，没保证它说的是这条链上的事。
            a = e.prev_anchor_attestation
            if a is not None:
                if e.epoch_id == 0:
                    problems.append("epoch 0: 之前没有 epoch，不应携带锚定判定")
                else:
                    prev_seal = self._epochs[e.epoch_id - 1]
                    if a.epoch_id != prev_seal.epoch_id:
                        problems.append(
                            f"epoch {e.epoch_id}: 锚定判定指向 epoch {a.epoch_id}，"
                            f"应为 {prev_seal.epoch_id}")
                    elif a.anchored_hash != prev_seal.epoch_hash():
                        # 上一个 epoch 被改过，或者这条判定是从别处搬来的。
                        problems.append(
                            f"epoch {e.epoch_id}: 锚定判定里的 anchored_hash "
                            f"与 epoch {a.epoch_id} 的实际哈希不符")
                    if (a.token_sha256 and prev_seal.tsa_token
                            and a.token_sha256 != hashlib.sha256(
                                base64.b64decode(prev_seal.tsa_token)).hexdigest()):
                        problems.append(
                            f"epoch {e.epoch_id}: 锚定判定说的不是 epoch "
                            f"{a.epoch_id} 里存着的那个 token")

            prev_e = e.epoch_hash()
            expect_start = e.end_seq + 1
        return problems

    def unsealed_count(self) -> int:
        """还没被任何 epoch 覆盖的记录条数 —— 也就是当前的暴露窗口。

        这些记录只受前向链保护，而前向链挡不住「从这里往后整段重建」。
        封存并锚定之前，它们不构成对抗自己的证据。生产环境应当监控这个值，
        它持续增长意味着封存或锚定停了。
        """
        covered = self._epochs[-1].end_seq + 1 if self._epochs else 0
        return max(0, len(self._records) - covered)

    # ---- 封存 ----
    def attach_anchor(self, anchor) -> None:
        """把一次锚定的结果回写进对应的 epoch。

        做两件事：
          1. 把 token 写回 epoch.tsa_token（此前调用方只能自己去动 _epochs，
             那是内部结构，不该是公开用法）；
          2. 把这次锚定的 eIDAS 合格判定排队，交给**下一个** seal_epoch()
             写进它的被哈希体，从而被下一次锚定的时间戳覆盖。

        第 2 步为什么不能就地写进本 epoch：本 epoch 的 epoch_hash 已经被盖过
        戳了，往里加任何东西都会让那个时间戳失效。见 AnchorAttestation 的注释。

        anchor 未成功（.ok 为假）时只排队判定、不写 token —— 一个失败的锚定
        没有 token 可写，但"这次尝试打到的 TSA 不合格"仍然是一条值得留痕的事实。
        """
        idx = next((i for i, e in enumerate(self._epochs)
                    if e.epoch_id == anchor.epoch_id), None)
        if idx is None:
            raise ValueError(f"epoch {anchor.epoch_id} 不在本账本内")

        if anchor.token_b64:
            self._epochs[idx] = replace(self._epochs[idx], tsa_token=anchor.token_b64)

        token_sha = None
        if anchor.token_b64:
            token_sha = hashlib.sha256(anchor.token_bytes()).hexdigest()
        self._pending_attestation = AnchorAttestation(
            epoch_id=anchor.epoch_id,
            anchored_hash=anchor.anchored_hash,
            tsa_url=anchor.tsa_url,
            token_sha256=token_sha,
            tsa_qualified=anchor.tsa_qualified,
            eutl_ref=anchor.eutl_ref,
            qualified_checked_at=anchor.qualified_checked_at,
            eutl_snapshot_sha256=getattr(anchor, "eutl_snapshot_sha256", None),
        )

    def unbound_anchor_count(self) -> int:
        """已排队但还没被任何 epoch 哈希覆盖的锚定判定条数（0 或 1）。

        与 unsealed_count() 是同一类指标，量的是另一个暴露窗口：判定已经做出，
        但还没有被时间戳保护，此刻它仍然可以被改而不留痕。再封一个 epoch
        并锚定它，这个窗口就关上了。

        账本永远至少有一次锚定判定是悬空的——最后那次。这不是缺陷，是这个
        结构的固有性质，和"最后一批记录还没被封存"是同一回事。要它归零，
        就得再封一个 epoch（哪怕只装一条心跳记录）并锚定。
        """
        return 1 if self._pending_attestation is not None else 0

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
            prev_anchor_attestation=self._pending_attestation,
        )
        self._pending_attestation = None
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
        """只校验结构：记录内容 → record_hash → 包含证明 → merkle_root。

        ⚠ 这个函数**不检查时间戳**，因此它的 True 不代表这份披露包
        可以拿去举证。它证明的只是「这条记录属于这个 Merkle 根」——
        而那个根是谁算的、有没有被第三方签过，它一概不问。
        一个自己伪造的账本能轻松让这里返回 True。

        要的是完整证据链就用 verify.verify_bundle()，它一路查到
        TSA 签名和证书链。本函数留在这里是给零依赖环境做结构自检用的。
        """
        try:
            if hash_obj(bundle["record"]) != bundle["record_hash"]:
                return False
            return verify_inclusion(
                bundle["record_hash"],
                [tuple(p) for p in bundle["proof"]],
                bundle["epoch"]["merkle_root"],
            )
        except (KeyError, TypeError, ValueError):
            # 结构不对就是没通过。让异常穿出去的话，调用方写
            # `if verify_disclosure(b):` 会直接崩，而不是走到 else 分支。
            return False

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
# 未完成的部分（按优先级）
# --------------------------------------------------------------------------
# RFC 3161 外部锚定已在 anchor.py 落地，验证在 verify.py。剩下的是：
#
# 1. append-only 存储后端：S3 Object Lock(COMPLIANCE 模式) / 仅 INSERT 权限的表。
#    内存 list 只是参考实现，重启即失。这是当前离生产最远的一块。
# 2. 保留策略：高风险系统最低 6 个月，生物识别/执法类 24 个月。
#    本库不实现留存，见 docs/article12.md 里标为「需外部配套」的那几行。
# 3. OTel 导出：把 record_hash 作为 span attribute 写进现有 trace，
#    使 tg-attest 与 Langfuse/Arize 共存而非竞争。
# 4. ReplayGate：基于 evidence_index() 实现，是差异化最强的一层，但依赖
#    本模块先跑起来积累历史快照。
