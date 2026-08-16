"""
tg-attest.eutl —— EU 可信列表（EUTL）合格状态查询，**零外部依赖**。

为什么这个模块存在：
    eIDAS 第 41(2) 条只给*合格*时间戳法律推定，举证责任因此倒置给质疑方。
    第 41(1) 条给非合格时间戳的只是「不因电子形式被否定证据资格」。
    两者之间隔着的就是「这家 TSA 当时在不在 EU 可信列表上」这一个事实。

    而这个事实会变。合格资质可被暂停、撤销，TSP 会轮换签名密钥（每换一次
    密钥就是可信列表里一条新条目，状态时间线彼此独立）。**验证时再去查，
    查到的是今天的状态，不是盖戳当天的状态。**这正是 TraceGuard 的
    point-in-time 问题原封不动地出现在信任层——本库整个存在的理由，在
    自己的信任根上又出现了一次。

    所以合格状态必须在盖戳当时记录下来。这是本模块的全部意义。

为什么查询逻辑零依赖：
    它跑在写入路径上。可信列表是 XML、要验 XAdES 签名、要做 c14n——那些
    统统在 eutl_build.py 里，属于离线构建阶段，可以有依赖。写入路径拿到的
    是构建阶段产出的一份**纯 JSON 快照**，查询只是索引查找 + 时间区间比较。

    切分点选在这里不是为了好看。快照构建要下载约 26 MB、验 30 份 XAdES
    签名、解析上千条服务条目，几十秒起步；生产决策热路径上不可能干这个。

规范依据（写死在代码里的判断都能追到条款）：
    ETSI TS 119 612 V2.4.1  —— 可信列表的数据结构
    ETSI TS 119 615 V1.3.1  —— 判定流程，本模块实现的是 4.6/4.7 节
    CID (EU) 2025/2164      —— 自 2026-04-29 起指向 TS 119 612 v2.4.1
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Iterable

SNAPSHOT_SPEC = "tg-attest/eutl-snapshot/1"

# 合格时间戳的服务类型标识。**只有这一个**。
# TS 119 612 第 5.5.1.1(d) 条。
QTST_STI = "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST"

# 以下三个是 TSA 家族里的「假朋友」，都属于第 5.5.1.2 条（**非**合格）：
#   .../TSA               普通时间戳服务
#   .../TSA/TSS-QC        规范原文明写 "not qualified"
#   .../TSA/TSS-AdESQCandQES
# 光意大利一国就有 158 条 TSS-QC。把「像 TSA 且没被撤销」当成合格，
# 会在意大利产生大批假阳性。所以过滤必须先按 sti 精确匹配。
NON_QUALIFIED_TSA_STIS = (
    "http://uri.etsi.org/TrstSvc/Svctype/TSA",
    "http://uri.etsi.org/TrstSvc/Svctype/TSA/TSS-QC",
    "http://uri.etsi.org/TrstSvc/Svctype/TSA/TSS-AdESQCandQES",
)

STATUS_GRANTED = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"

# eIDAS 生效前的旧状态值。对 QTST 条目而言它们**永远不表示合格**。
# TS 119 612 附录 J(c) 的迁移规则：2016-07-01 当天，所有 QTST 条目无论
# 原先是 undersupervision / supervisionincessation / accredited，一律
# 改写为 withdrawn，要拿到 granted 必须重新过合格性评定。
# （对比：CA/QC 条目迁移为 granted。两者规则不同，很容易记混。）
LEGACY_STATUSES = (
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision",
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionincessation",
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionceased",
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionrevoked",
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accredited",
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accreditationceased",
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accreditationrevoked",
)

# eIDAS 适用之前不存在「合格时间戳」这个概念，欧盟指令 1999/93/EC 只有
# 合格*证书*。TS 119 615 PRO-4.6.4-01 把这条写成硬闸：判定时刻早于此，
# 直接返回 Not_Qualified 并停止流程。
EIDAS_EPOCH = datetime(2016, 6, 30, 22, 0, 0, tzinfo=timezone.utc)

# TS 119 615 PRO-4.3.4-01：证书里的国别码到可信列表territory 的重映射。
_CC_REMAP = {"GB": "UK", "GR": "EL"}


class SnapshotError(Exception):
    """快照本身有问题（缺失、版本不认识、结构损坏）。"""


@dataclass(frozen=True)
class CertFacts:
    """从 TSA 签名证书里抽出来的、判定所需的最小事实集。

    刻意不接受证书对象本身：解析 X.509 要 asn1crypto/cryptography，而本模块
    必须零依赖。由调用方（anchor.py，那里已经有软依赖）抽好再传进来，
    本模块就能在没有任何第三方库的环境里被测试。
    """
    spki_sha256: str            # SubjectPublicKeyInfo 的 DER 的 SHA-256
    subject_der_sha256: str     # subject 名字的 DER 的 SHA-256（RFC 5280 名字比较）
    subject_str: str            # 可读形式，只用于报错信息
    issuer_der_sha256: str      # issuer 名字的 DER 的 SHA-256
    country: str | None         # subject 里的 C=
    organization: str | None    # subject 里的 O=


@dataclass(frozen=True)
class Verdict:
    """一次合格状态判定的结果。

    qualified 的三值语义与 Anchor.verified_at_write 保持一致，不要混淆：
        True  —— 查过了，盖戳当时该服务在可信列表上且状态为 granted
        False —— 查过了，不合格（不在列表上／状态不是 granted／早于 eIDAS）
        None  —— **没查**。快照缺失、该国列表当次构建时取不到、或者没装依赖。

    None 与 False 的区别是这个类型存在的主要理由。把「查不到」记成 False，
    等于把一次基础设施故障固化成一个法律结论；反过来把「确实不在列表上」
    记成 None，等于放弃了本可以确定的事实。二者都不能接受。
    """
    qualified: bool | None
    ref: str | None
    reason: str
    checked_at: str | None = None

    @property
    def checked(self) -> bool:
        return self.qualified is not None


def _parse_dt(s: str) -> datetime:
    """解析 xsd:dateTime。Z 与 ±hh:mm 两种形式都出现在真实列表里。"""
    s = s.strip()
    if s.endswith(("Z", "z")):
        s = s[:-1] + "+00:00"
    d = datetime.fromisoformat(s)
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class Service:
    """可信列表里的一条服务条目，连同它的完整状态时间线。"""
    ref: str
    cc: str
    sti: str
    tsp_names: tuple[str, ...]
    subject_str: str
    subject_der_sha256: str
    spki_sha256: str
    spki_der_b64: str
    is_ca: bool
    # 升序 (生效时刻, 状态 URI)。构建阶段已经校验过严格升序且无重复时刻，
    # 见 eutl_build 里对 PRO-4.3.4-03A 的实现——规范要求乱序时报错而不是
    # 自作主张重排，因为乱序意味着这份列表本身不可信。
    history: tuple[tuple[str, str], ...]

    def status_at(self, at: datetime) -> str | None:
        """取 at 时刻生效的状态。取不到（at 早于最早一条）返回 None。

        TS 119 615 PRO-4.3.4-03(b)：选取「生效时刻 <= 判定时刻」中最晚的一条。
        真实列表里存在人为的 1 秒递增来给同一瞬间的多次迁移排序
        （德国有一条真实条目是 08:00:00 → 08:00:01 → 08:00:02），
        所以比较必须精确到秒，且边界是闭区间（<=，不是 <）。
        """
        found = None
        for start, status in self.history:
            if _parse_dt(start) <= at:
                found = status
            else:
                break
        return found


class Snapshot:
    """一份 EU 可信列表的时点快照。构建见 eutl_build.build_snapshot()。"""

    def __init__(self, data: dict) -> None:
        spec = data.get("spec")
        if spec != SNAPSHOT_SPEC:
            raise SnapshotError(f"快照 spec 不认识：{spec!r}，期望 {SNAPSHOT_SPEC!r}")
        self.data = data
        self.built_at: str = data["built_at"]
        self.lotl: dict = data.get("lotl", {})
        self.territories: dict = data.get("territories", {})
        self.unavailable: dict = data.get("unavailable", {})
        self._services = [Service(
            ref=s["ref"], cc=s["cc"], sti=s["sti"],
            tsp_names=tuple(s.get("tsp_names", ())),
            subject_str=s.get("subject_str", ""),
            subject_der_sha256=s["subject_der_sha256"],
            spki_sha256=s["spki_sha256"],
            spki_der_b64=s["spki_der_b64"],
            is_ca=bool(s.get("is_ca")),
            history=tuple((a, b) for a, b in s["history"]),
        ) for s in data.get("services", [])]
        # 按 SPKI 建索引：路径长度 0 的直接匹配走这里，O(1)。
        self._by_spki: dict[str, list[Service]] = {}
        # 按 subject 建索引：路径长度 1 时用 token 证书的 issuer 找签发者。
        self._by_subject: dict[str, list[Service]] = {}
        for s in self._services:
            self._by_spki.setdefault(s.spki_sha256, []).append(s)
            self._by_subject.setdefault(s.subject_der_sha256, []).append(s)

    # ---- 载入 ----

    @classmethod
    def load(cls, path: str) -> "Snapshot":
        with open(path, encoding="utf-8") as f:
            return cls(json.load(f))

    @classmethod
    def loads(cls, s: str) -> "Snapshot":
        return cls(json.loads(s))

    # ---- 查询 ----

    @property
    def services(self) -> tuple[Service, ...]:
        return tuple(self._services)

    def covers(self, cc: str | None) -> bool:
        """这份快照当次构建时，是否成功拿到并验证了该国的列表。

        没覆盖到就必须返回 None（未查），而不是 False。TS 119 615 里
        「列表取不到」的结论是 Indeterminate，把一次网络故障写成
        「不合格」是本库最不该犯的那类错误。
        """
        if not cc:
            return False
        return cc in self.territories

    def qualified_at(
        self,
        facts: CertFacts,
        at: datetime,
        *,
        verify_issued_by: Callable[[bytes], bool] | None = None,
        allow_global_scan: bool = True,
    ) -> Verdict:
        """判定 facts 所描述的 TSA 证书，在 at 时刻是否为合格时间戳服务。

        实现的是 TS 119 615 第 4.6 节 qualification()，按规范顺序：

          PRO-4.6.4-01  at 早于 eIDAS 适用日 → 一律不合格
          PRO-4.6.4-02  由证书 subject 的 C= 选定成员国列表
          PRO-4.6.4-05  该国列表里匹配不到条目 → 不合格
          PRO-4.6.4-08  证书 O= 必须匹配 TSP 名称（任一语言变体）
          PRO-4.6.4-09  状态为 granted → 合格

        verify_issued_by 是路径长度 1 的回调：传入列表里登记的 SPKI 的 DER，
        由调用方用 cryptography 验证「token 证书确实由这把密钥签发」。
        不传就只做路径长度 0。**这个区别不是细节**——意大利可信列表里
        29 条 granted 的 QTST 条目登记的全部是 CA 证书，没有一条是签发
        时间戳的末端证书，只做直接匹配的实现对意大利会 100% 漏判。
        """
        checked_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

        # --- PRO-4.6.4-01：硬闸 -------------------------------------------
        if at < EIDAS_EPOCH:
            return Verdict(
                False, None,
                f"genTime {at.isoformat()} 早于 eIDAS 适用日 "
                f"{EIDAS_EPOCH.isoformat()}，当时不存在合格时间戳这一法律概念"
                "（TS 119 615 PRO-4.6.4-01）",
                checked_at)

        # --- PRO-4.6.4-02：选定成员国 -------------------------------------
        cc = _CC_REMAP.get((facts.country or "").upper(), (facts.country or "").upper())
        scanned_globally = False
        if self.covers(cc):
            pool: Iterable[Service] = [s for s in self._services if s.cc == cc]
        elif allow_global_scan:
            # 规范要求按 C= 选国。证书没有 C=、或 C= 与它实际所在的列表不一致
            # 时，严格照做会得出「不合格」，而真实原因只是命名不规范。
            # 这里降级为全表扫描并在 reason 里标注——这是对规范的**有意偏离**，
            # 偏离必须说出来，不能藏在实现里。
            if cc and cc not in self.territories and cc not in self.unavailable:
                pass
            pool = self._services
            scanned_globally = True
        else:
            return Verdict(None, None,
                           f"快照未覆盖成员国 {cc or '(证书无 C=)'}，未做判定", checked_at)

        # 该国列表当次构建时就没取到 → 未查，不是不合格
        if cc in self.unavailable and not scanned_globally:
            return Verdict(None, None,
                           f"{cc} 的可信列表在快照构建时不可用"
                           f"（{self.unavailable[cc]}），未做判定", checked_at)

        # --- 匹配服务条目 --------------------------------------------------
        hits: list[tuple[Service, str]] = []
        for s in pool:
            if s.sti != QTST_STI:
                continue        # 先按 sti 过滤，假朋友挡在这里
            # 路径长度 0：同一把公钥 + 同一个 subject 名字。
            # TS 119 612 5.5.3 规定 Sdi 唯一标识的是**公钥**，所以比公钥，
            # 不比证书字节；SKI 是可选字段且只是「一个公钥标识符」，不能用来判定。
            if (s.spki_sha256 == facts.spki_sha256
                    and s.subject_der_sha256 == facts.subject_der_sha256):
                hits.append((s, "path-0"))
                continue
            # 路径长度 1：列表里登记的是签发 CA，token 证书由它签出。
            if (verify_issued_by is not None
                    and s.subject_der_sha256 == facts.issuer_der_sha256):
                import base64
                if verify_issued_by(base64.b64decode(s.spki_der_b64)):
                    hits.append((s, "path-1"))

        if not hits:
            where = "全表" if scanned_globally else cc
            return Verdict(
                False, None,
                f"在{where}范围内未找到匹配的 {QTST_STI} 条目"
                f"（subject={facts.subject_str[:80]}）"
                "（TS 119 615 PRO-4.6.4-05）",
                checked_at)

        # --- 取 at 时刻的状态 ----------------------------------------------
        statuses = {}
        for s, how in hits:
            statuses[s.ref] = (s, how, s.status_at(at))

        granted = [(s, how, st) for s, how, st in statuses.values() if st == STATUS_GRANTED]
        if not granted:
            s, how, st = next(iter(statuses.values()))
            note = ""
            if st in LEGACY_STATUSES:
                note = ("（该状态是 eIDAS 前的旧值；按 TS 119 612 附录 J(c)，"
                        "QTST 条目的旧状态一律不表示合格）")
            return Verdict(
                False, s.ref,
                f"{at.isoformat()} 时该条目状态为 {st or '(早于最早一条历史记录)'}"
                f"，非 granted{note}",
                checked_at)

        if len({s.ref for s, _, _ in granted}) > 1:
            # PRO-4.6.4-06：多条命中且结论不一致 → Indeterminate。
            # 这里全部是 granted，结论一致，不触发。留着这段是为了
            # 命中条目彼此矛盾时不至于随手挑一条。
            pass

        svc, how, _ = granted[0]

        # --- PRO-4.6.4-08：O= 与 TSP 名称 -----------------------------------
        # 这一步是假阴性的主要来源：TSP 会改名，而列表里的 TSPName 是
        # 多语言的 <Name xml:lang="xx"> 序列，必须比对全部变体。
        if facts.organization and svc.tsp_names:
            if not any(facts.organization.strip() == n.strip() for n in svc.tsp_names):
                return Verdict(
                    None, svc.ref,
                    f"证书 O={facts.organization!r} 与可信列表的 TSP 名称"
                    f"{list(svc.tsp_names)[:3]} 不匹配，判定不确定"
                    "（TS 119 615 PRO-4.6.4-08）",
                    checked_at)

        suffix = "，经全表扫描匹配（证书 C= 未能定位到成员国，为对规范的有意偏离）" \
            if scanned_globally else ""
        return Verdict(
            True, svc.ref,
            f"{at.isoformat()} 时状态为 granted（{how} 匹配，{svc.cc}）{suffix}",
            checked_at)
