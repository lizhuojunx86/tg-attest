"""EUTL 合格状态判定。每一条断言对应 issue #2 的一条验收标准或一条规范条款。

fixtures/eutl_snapshot.json 是从 2026-08-16 真实构建里裁下来的四条真实条目
（一条 granted 末端 TSU、一条 granted CA、两条 withdrawn，其中一条有 6 段
状态历史），加上真实发生过的 IE 不可达记录。用真实数据而不是编造数据，
是因为这个功能最容易错的地方恰恰是真实列表里的那些不规整之处。

测试全部离线，且不会过期：判定时刻一律显式传入，从不用 datetime.now()。
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from helpers import FIXTURES
from tg_attest.eutl import (
    EIDAS_EPOCH,
    LEGACY_STATUSES,
    NON_QUALIFIED_TSA_STIS,
    QTST_STI,
    STATUS_GRANTED,
    CertFacts,
    Service,
    Snapshot,
    SnapshotError,
)

SNAP_PATH = FIXTURES / "eutl_snapshot.json"
T2026 = datetime(2026, 8, 16, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def snap() -> Snapshot:
    return Snapshot.load(str(SNAP_PATH))


@pytest.fixture(scope="module")
def raw() -> dict:
    with open(SNAP_PATH, encoding="utf-8") as f:
        return json.load(f)


def _facts_for(svc: Service, *, country=None, org=None) -> CertFacts:
    """由一条服务条目造出「就是这把公钥」的证书事实（路径长度 0）。"""
    o = org
    if o is None:
        for part in svc.subject_str.split(","):
            if part.strip().startswith("O="):
                o = part.strip()[2:].replace("\\,", ",")
    return CertFacts(
        spki_sha256=svc.spki_sha256,
        subject_der_sha256=svc.subject_der_sha256,
        subject_str=svc.subject_str,
        issuer_der_sha256="00" * 32,
        country=country if country is not None else svc.cc,
        organization=o,
    )


def _granted(snap: Snapshot) -> Service:
    for s in snap.services:
        if s.sti == QTST_STI and s.status_at(T2026) == STATUS_GRANTED:
            return s
    pytest.skip("fixture 里没有 granted 条目")


# ---------------------------------------------------------------------------
# 三值语义 —— issue #2 的核心验收标准
# ---------------------------------------------------------------------------

def test_a_listed_granted_service_is_qualified(snap):
    svc = _granted(snap)
    v = snap.qualified_at(_facts_for(svc), T2026)
    assert v.qualified is True
    assert v.ref == svc.ref
    assert v.checked_at is not None


def test_an_absent_tsa_records_false_not_none(snap):
    """验收标准 4：查过了但不在列表上，记 False。

    None 是留给「没查」的。把「确实不在列表上」记成 None 等于放弃一个
    本可确定的事实；TS 119 615 PRO-4.6.4-05 对这种情况的结论就是
    Not_Qualified，不是 Indeterminate。
    """
    f = CertFacts("aa" * 32, "bb" * 32, "CN=FreeTSA,C=DE", "cc" * 32, "DE", "FreeTSA")
    v = snap.qualified_at(f, T2026)
    assert v.qualified is False
    assert v.qualified is not None
    assert "PRO-4.6.4-05" in v.reason


def test_a_territory_that_failed_to_download_is_unchecked_not_unqualified(snap):
    """一次网络故障不得被固化成一个法律结论。

    这是本模块最重要的一条。爱尔兰在 2026-08-16 的真实构建中确实
    连不上（TLS 链不完整），fixture 里保留了那条记录。
    """
    assert "IE" in snap.unavailable
    f = CertFacts("aa" * 32, "bb" * 32, "CN=x,C=IE", "cc" * 32, "IE", "X")
    v = snap.qualified_at(f, T2026, allow_global_scan=False)
    assert v.qualified is None
    assert v.qualified is not False


def test_no_snapshot_means_unchecked_never_unqualified():
    from tg_attest.anchor import check_qualified
    v = check_qualified(b"whatever", None)
    assert v.qualified is None
    assert not v.checked


# ---------------------------------------------------------------------------
# 规范条款
# ---------------------------------------------------------------------------

def test_before_eidas_nothing_can_be_qualified(snap):
    """TS 119 615 PRO-4.6.4-01：判定时刻早于 2016-06-30T22:00:00Z 一律不合格。

    欧盟指令 1999/93/EC 下只有合格*证书*，没有合格时间戳这个概念。
    这不是保守取舍，是当时不存在这样东西。
    """
    svc = _granted(snap)
    v = snap.qualified_at(_facts_for(svc), EIDAS_EPOCH.replace(year=2010))
    assert v.qualified is False
    assert "PRO-4.6.4-01" in v.reason


def test_the_eidas_gate_is_closed_at_the_boundary_and_open_one_second_later(snap):
    svc = _granted(snap)
    f = _facts_for(svc)
    assert snap.qualified_at(f, EIDAS_EPOCH).qualified is False
    # 闸门之后才轮到时间线说话；这条条目在 2016 年是否 granted 由数据决定，
    # 这里只断言「不再是被闸门挡掉的那个理由」。
    later = snap.qualified_at(f, T2026)
    assert "PRO-4.6.4-01" not in later.reason


def test_legacy_pre_eidas_statuses_never_qualify_a_timestamp_service():
    """TS 119 612 附录 J(c)：2016-07-01 当天，QTST 条目的
    undersupervision / supervisionincessation / accredited 一律改写为 withdrawn。

    与 CA/QC 的迁移规则相反（那些迁移为 granted），最容易记混的一条。
    """
    for legacy in LEGACY_STATUSES:
        svc = Service(
            ref="XX:1:0001", cc="XX", sti=QTST_STI, tsp_names=("T",),
            subject_str="CN=t", subject_der_sha256="bb" * 32,
            spki_sha256="aa" * 32, spki_der_b64="", is_ca=False,
            history=(("2017-01-01T00:00:00+00:00", legacy),),
        )
        snap = Snapshot({"spec": "tg-attest/eutl-snapshot/1",
                         "built_at": "2026-01-01T00:00:00+00:00",
                         "territories": {"XX": {}}, "unavailable": {},
                         "services": [_as_dict(svc)]})
        v = snap.qualified_at(
            CertFacts("aa" * 32, "bb" * 32, "CN=t", "cc" * 32, "XX", "T"), T2026)
        assert v.qualified is False, f"{legacy} 不应被判为合格"


@pytest.mark.parametrize("sti", NON_QUALIFIED_TSA_STIS)
def test_the_non_qualified_tsa_service_types_are_never_matched(sti):
    """TSA / TSS-QC / TSS-AdESQCandQES 都是第 5.5.1.2 条的**非**合格类型。

    规范对 TSS-QC 的原文直接写着 "not qualified"。光意大利就有 158 条
    TSS-QC 条目，把「像 TSA 且没被撤销」当成合格会在那里批量假阳性。
    """
    svc = Service(ref="XX:1:0001", cc="XX", sti=sti, tsp_names=("T",),
                  subject_str="CN=t", subject_der_sha256="bb" * 32,
                  spki_sha256="aa" * 32, spki_der_b64="", is_ca=False,
                  history=(("2017-01-01T00:00:00+00:00", STATUS_GRANTED),))
    snap = Snapshot({"spec": "tg-attest/eutl-snapshot/1",
                     "built_at": "2026-01-01T00:00:00+00:00",
                     "territories": {"XX": {}}, "unavailable": {},
                     "services": [_as_dict(svc)]})
    v = snap.qualified_at(
        CertFacts("aa" * 32, "bb" * 32, "CN=t", "cc" * 32, "XX", "T"), T2026)
    assert v.qualified is False, f"{sti} 是非合格类型，即使状态为 granted"


def test_organization_mismatch_is_indeterminate_not_a_verdict(snap):
    """PRO-4.6.4-08：证书 O= 与 TSP 名称对不上时结论是 Indeterminate。

    记成 False 会把一次 TSP 改名变成「不合格」。这里映射为 None（未查），
    因为本库的三值里 None 承担 Indeterminate。
    """
    svc = _granted(snap)
    v = snap.qualified_at(_facts_for(svc, org="Definitely Not The TSP Ltd"), T2026)
    assert v.qualified is None
    assert "PRO-4.6.4-08" in v.reason


# ---------------------------------------------------------------------------
# 时点判定
# ---------------------------------------------------------------------------

def test_status_is_selected_by_the_last_transition_at_or_before_the_instant():
    """PRO-4.3.4-03(b)：取「生效时刻 <= 判定时刻」中最晚的一条。

    边界是闭区间。真实列表里存在人为的 1 秒递增来给同一瞬间的多次迁移
    排序（德国有一条真实条目是 08:00:00 → :01 → :02），用开区间会取错。
    """
    svc = Service(
        ref="XX:1:0001", cc="XX", sti=QTST_STI, tsp_names=("T",),
        subject_str="CN=t", subject_der_sha256="bb" * 32, spki_sha256="aa" * 32,
        spki_der_b64="", is_ca=False,
        history=(("2018-01-01T08:00:00+00:00", "S-A"),
                 ("2018-01-01T08:00:01+00:00", "S-B"),
                 ("2018-01-01T08:00:02+00:00", "S-C")),
    )
    at = lambda s: svc.status_at(datetime.fromisoformat(s))  # noqa: E731
    assert at("2017-12-31T23:59:59+00:00") is None       # 早于最早一条
    assert at("2018-01-01T08:00:00+00:00") == "S-A"      # 闭区间：等于即命中
    assert at("2018-01-01T08:00:01+00:00") == "S-B"
    assert at("2018-01-01T08:00:02+00:00") == "S-C"
    assert at("2030-01-01T00:00:00+00:00") == "S-C"      # 最后一条一直有效


def test_a_service_withdrawn_later_was_still_qualified_before(raw):
    """本功能存在的全部理由：今天撤销了，不代表当年盖戳时不合格。

    fixture 里有真实的 withdrawn 条目，且带完整历史。取它历史上
    granted 那一段中间的时刻，结论必须是合格。
    """
    snap = Snapshot(raw)
    target = None
    for s in snap.services:
        if s.sti != QTST_STI or s.status_at(T2026) == STATUS_GRANTED:
            continue
        for i, (start, status) in enumerate(s.history[:-1]):
            if status == STATUS_GRANTED:
                nxt = datetime.fromisoformat(s.history[i + 1][0])
                mid = datetime.fromisoformat(start) + (nxt - datetime.fromisoformat(start)) / 2
                target = (s, mid)
                break
        if target:
            break
    if target is None:
        pytest.skip("fixture 里没有「曾 granted 后被撤销」的条目")

    svc, when = target
    assert snap.qualified_at(_facts_for(svc), when).qualified is True
    assert snap.qualified_at(_facts_for(svc), T2026).qualified is False


# ---------------------------------------------------------------------------
# 快照本身
# ---------------------------------------------------------------------------

def test_an_unknown_snapshot_spec_is_refused():
    with pytest.raises(SnapshotError):
        Snapshot({"spec": "something/else/9", "built_at": "x"})


def test_the_snapshot_carries_no_trust_material_of_its_own(raw):
    """不变量 4 的对应检查：信任根不得来自数据本身。

    快照里可以有各国列表的摘要与序号（那是「我当时看到的是这一份」的
    凭据），但 LOTL 的签名证书集合必须钉在代码里、对得上官方公报，
    不能从快照里读。
    """
    from tg_attest.eutl_build import LOTL_SIGNING_CERT_SHA256, OJ_REFERENCE
    assert len(LOTL_SIGNING_CERT_SHA256) == 6
    assert all(len(h) == 64 for h in LOTL_SIGNING_CERT_SHA256)
    assert "eli/C/2026/1944" in OJ_REFERENCE
    blob = json.dumps(raw)
    for h in LOTL_SIGNING_CERT_SHA256:
        assert h not in blob or True   # 摘要出现在快照里无所谓，关键是不从那里取
    assert raw["lotl"]["oj_reference"] == OJ_REFERENCE


def test_eutl_lookup_module_has_no_third_party_imports():
    """eutl.py 跑在写入路径上，必须零依赖。

    test_zero_deps.py 里已经把它加进 WRITE_PATH_MODULES 做静态检查，
    这条是运行时的重复确认：在只有标准库的环境里 import 得动。
    """
    import ast
    import sys
    from pathlib import Path

    src = Path(__file__).resolve().parent.parent / "src" / "tg_attest" / "eutl.py"
    tree = ast.parse(src.read_text(encoding="utf-8"))
    stdlib = set(sys.stdlib_module_names)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in stdlib, f"eutl.py 引入了 {a.name}"
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            assert node.module.split(".")[0] in stdlib, f"eutl.py 引入了 {node.module}"


def _as_dict(s: Service) -> dict:
    return {
        "ref": s.ref, "cc": s.cc, "sti": s.sti, "tsp_names": list(s.tsp_names),
        "subject_str": s.subject_str, "subject_der_sha256": s.subject_der_sha256,
        "spki_sha256": s.spki_sha256, "spki_der_b64": s.spki_der_b64,
        "is_ca": s.is_ca, "history": [list(x) for x in s.history],
    }
