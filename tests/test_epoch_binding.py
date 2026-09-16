"""把锚定判定绑进哈希链（issue #3）。

核心主张只有一句：epoch N 的 eIDAS 合格判定写在 epoch N+1 的被哈希体里，
因此改动它会让 N+1 的时间戳验不过。

这个文件里最重要的两条恰好方向相反：
  · test_attaching_an_anchor_does_not_change_the_hash_that_was_stamped
    —— 判定绝不能改到**本** epoch 头上，否则刚取回的时间戳当场失效。
       这是不变量 5，本项目在 tsa_token 上已经踩过一次。
  · test_tampering_with_any_attestation_field_changes_the_binding_epoch_hash
    —— 但它必须真的被下一个 epoch 的哈希盖住，否则这个 issue 白做。
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json

import pytest

from helpers import FIXTURES
from tg_attest.record import AnchorAttestation, EpochSeal, Ledger
from tg_attest.verify import export_bundle, verify_bundle


def _seal(**kw) -> EpochSeal:
    base = dict(epoch_id=1, start_seq=0, end_seq=0, merkle_root="ab" * 32,
                prev_epoch_hash="cd" * 32, sealed_at="2026-08-16T00:00:00+00:00")
    base.update(kw)
    return EpochSeal(**base)


def _att(**kw) -> AnchorAttestation:
    base = dict(epoch_id=0, anchored_hash="ef" * 32, tsa_url="http://tsa.example/x",
                token_sha256="12" * 32, tsa_qualified=True, eutl_ref="BE:81:0001",
                qualified_checked_at="2026-08-16T00:00:00+00:00",
                eutl_snapshot_sha256="34" * 32)
    base.update(kw)
    return AnchorAttestation(**base)


# ---------------------------------------------------------------------------
# 向后兼容：新字段不得惊动任何已经发出去的披露包
# ---------------------------------------------------------------------------

def test_an_epoch_without_an_attestation_hashes_exactly_as_it_did_before():
    """判定为 None 时整个键不出现在被哈希的字典里。

    verify_bundle 是拿披露包里的 epoch 字典去构造 EpochSeal 的。新字段一旦
    带上默认值 None 并参与哈希，0.1.0 时代那些不含此键的包会被补上一个 null，
    哈希随之改变——**每一个已经发出去的披露包当场失效**。
    这条把那个行为钉死：值是这个 SHA-256，改了就是破坏了向后兼容。
    """
    s = _seal()
    assert s.prev_anchor_attestation is None
    assert s.epoch_hash() == \
        "e99491ded5101ea982949745b33e38e6c80d26f85baa296ba174f2b4f7274d9d"


def test_the_shipped_v0_1_0_disclosure_bundle_still_verifies_offline():
    """仓库里那份真实披露包是 0.1.0 时代产出的，不含新字段。

    它是 README 里那条「三十秒自己验一遍」的依据，也是 CI 里
    verify-bundle 工作流跑的东西。这条一旦红，说明哈希兼容性被打破了。
    """
    with open(FIXTURES / "decision_0000.json", encoding="utf-8") as f:
        bundle = json.load(f)
    assert "prev_anchor_attestation" not in bundle["epoch"]
    ca = (FIXTURES / "freetsa_ca.pem").read_bytes()
    assert verify_bundle(bundle, ca).ok


# ---------------------------------------------------------------------------
# 不变量 5：判定绝不能改到被盖戳的那个 epoch 头上
# ---------------------------------------------------------------------------

def test_attaching_an_anchor_does_not_change_the_hash_that_was_stamped(led_with_epoch):
    """这是整个设计被逼成"往后挪一格"的原因。

    合格状态要拿到 token 才算得出来，而 epoch_hash 是被盖戳的**输入**。
    就地写回等于在盖完戳之后修改被盖的东西，时间戳当场失效。
    """
    led, e0, before = led_with_epoch
    led.attach_anchor(_FakeAnchor(epoch_id=0, anchored_hash=before))
    assert led._epochs[0].epoch_hash() == before, \
        "回写锚定结果改变了已经被盖戳的 epoch_hash —— 时间戳已失效"


def test_the_attestation_lands_in_the_next_epoch_not_this_one(led_with_epoch):
    led, e0, before = led_with_epoch
    led.attach_anchor(_FakeAnchor(epoch_id=0, anchored_hash=before))
    assert led._epochs[0].prev_anchor_attestation is None

    _append(led)
    e1 = led.seal_epoch()
    assert e1.prev_anchor_attestation is not None
    assert e1.prev_anchor_attestation.epoch_id == 0
    assert e1.prev_anchor_attestation.anchored_hash == before


# ---------------------------------------------------------------------------
# 绑定确实成立
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("field", [
    "epoch_id", "anchored_hash", "tsa_url", "token_sha256",
    "tsa_qualified", "eutl_ref", "qualified_checked_at", "eutl_snapshot_sha256",
])
def test_tampering_with_any_attestation_field_changes_the_binding_epoch_hash(field):
    """判定的每一个字段都必须参与哈希。

    逐字段参数化而不是整体改一下：漏掉某一个字段不参与哈希，整体测试照样
    通过，而那个字段恰好可能是 tsa_qualified —— 也就是唯一有法律后果的那个。
    """
    original = _seal(prev_anchor_attestation=_att())
    h = original.epoch_hash()
    cur = getattr(original.prev_anchor_attestation, field)
    other = False if isinstance(cur, bool) else (
        1 if isinstance(cur, int) else "tampered")
    tampered = _seal(prev_anchor_attestation=dataclasses.replace(
        original.prev_anchor_attestation, **{field: other}))
    assert tampered.epoch_hash() != h, f"改动 {field} 没有改变 epoch_hash"


def test_removing_the_attestation_entirely_is_also_detected():
    """降级攻击：把判定整段删掉。

    None 时键不出现（向后兼容需要），所以要确认「本来有、被删掉」与
    「本来就没有」哈希不同 —— 否则攻击者可以直接摘掉一条不利的判定。
    """
    with_att = _seal(prev_anchor_attestation=_att())
    without = _seal()
    assert with_att.epoch_hash() != without.epoch_hash()


# ---------------------------------------------------------------------------
# Ledger.verify 的结构校验
# ---------------------------------------------------------------------------

def test_verify_catches_an_attestation_pointing_at_the_wrong_epoch(led_two_epochs):
    led = led_two_epochs
    a = led._epochs[1].prev_anchor_attestation
    led._epochs[1] = dataclasses.replace(
        led._epochs[1], prev_anchor_attestation=dataclasses.replace(a, epoch_id=7))
    assert any("指向 epoch 7" in p for p in led.verify())


def test_verify_catches_an_attestation_whose_anchored_hash_does_not_match(led_two_epochs):
    """上一个 epoch 被改过，或者这条判定是从别的账本搬来的。

    没有这条校验，被哈希保护的就只是"一段不会被改的自由文本"——
    保证了它没被改，没保证它说的是这条链上的事。
    """
    led = led_two_epochs
    a = led._epochs[1].prev_anchor_attestation
    led._epochs[1] = dataclasses.replace(
        led._epochs[1],
        prev_anchor_attestation=dataclasses.replace(a, anchored_hash="99" * 32))
    assert any("anchored_hash" in p for p in led.verify())


def test_verify_catches_an_attestation_about_a_different_token(led_two_epochs):
    led = led_two_epochs
    a = led._epochs[1].prev_anchor_attestation
    led._epochs[1] = dataclasses.replace(
        led._epochs[1],
        prev_anchor_attestation=dataclasses.replace(a, token_sha256="77" * 32))
    assert any("token" in p for p in led.verify())


def test_verify_rejects_an_attestation_on_the_first_epoch(led_two_epochs):
    led = led_two_epochs
    led._epochs[0] = dataclasses.replace(
        led._epochs[0], prev_anchor_attestation=_att())
    assert any("epoch 0" in p for p in led.verify())


def test_a_clean_two_epoch_ledger_verifies(led_two_epochs):
    assert led_two_epochs.verify() == []


# ---------------------------------------------------------------------------
# 暴露窗口的可见性
# ---------------------------------------------------------------------------

def test_the_last_anchor_is_always_unbound_and_says_so(led_with_epoch):
    """账本永远至少有一次判定悬空——最后那次。

    这不是缺陷，是结构的固有性质，和「最后一批记录还没被封存」是同一回事。
    重要的是它可见：unbound_anchor_count() 不报出来，使用者会以为所有判定
    都受保护，而最后那条其实还能被随便改。
    """
    led, e0, before = led_with_epoch
    assert led.unbound_anchor_count() == 0        # 还没锚定
    led.attach_anchor(_FakeAnchor(epoch_id=0, anchored_hash=before))
    assert led.unbound_anchor_count() == 1        # 判定做了，还没被哈希覆盖
    _append(led)
    led.seal_epoch()
    assert led.unbound_anchor_count() == 0        # 被 epoch 1 盖住了


def test_attaching_an_anchor_for_an_unknown_epoch_is_refused(led_with_epoch):
    led, _, before = led_with_epoch
    with pytest.raises(ValueError, match="不在本账本内"):
        led.attach_anchor(_FakeAnchor(epoch_id=99, anchored_hash=before))


# ---------------------------------------------------------------------------
# 披露包
# ---------------------------------------------------------------------------

def test_export_refuses_include_binding_when_nothing_binds_it_yet(led_with_epoch):
    """悄悄导出一个不含绑定的包，使用者会以为判定受保护而其实没有。

    这与 0.1.0 里 export_bundle 对未锚定包的处理是同一条原则：
    导出时不说，等交出去才发现它证明不了什么，那时已经补不回来。
    """
    led, e0, before = led_with_epoch
    led.attach_anchor(_FakeAnchor(epoch_id=0, anchored_hash=before))
    with pytest.raises(ValueError, match="还没有被任何 epoch 哈希覆盖"):
        export_bundle(led, 0, "/tmp/_x.json", allow_unanchored=True,
                      include_binding=True)


def test_a_binding_that_points_at_another_epoch_is_reported(led_two_epochs, tmp_path):
    led = led_two_epochs
    p = str(tmp_path / "b.json")
    export_bundle(led, 0, p, allow_unanchored=True, include_binding=True)
    with open(p, encoding="utf-8") as f:
        b = json.load(f)
    b["binding_epoch"]["prev_anchor_attestation"]["anchored_hash"] = "aa" * 32
    r = verify_bundle(b, None)
    assert any("绑定" in k for k in r.attestations)


@pytest.mark.network
def test_end_to_end_the_binding_timestamp_covers_the_qualified_verdict(tmp_path):
    """联网：两次真实锚定，第二次的时间戳把第一次的判定盖住。

    篡改判定之后绑定校验必须失败，而主验证仍然通过 —— 后者是刻意的：
    是否合格是法律分类，不该决定一个披露包在技术上是否有效。
    """
    from tg_attest import AnchorQueue

    led = Ledger()
    _append(led)
    e0 = led.seal_epoch()
    q = AnchorQueue(("https://freetsa.org/tsr",))
    q.enqueue(e0.epoch_id, e0.epoch_hash())
    a0 = q.flush(timeout=30)
    assert a0 and a0.ok
    led.attach_anchor(a0)

    _append(led)
    e1 = led.seal_epoch()
    q.enqueue(e1.epoch_id, e1.epoch_hash())
    a1 = q.flush(timeout=30)
    assert a1 and a1.ok
    led.attach_anchor(a1)
    assert led.verify() == []

    p = str(tmp_path / "bound.json")
    export_bundle(led, 0, p, anchor=a0, include_binding=True)
    with open(p, encoding="utf-8") as f:
        b = json.load(f)
    ca = (FIXTURES / "freetsa_ca.pem").read_bytes()

    r = verify_bundle(b, ca)
    assert r.ok
    bound = [v for k, v in r.attestations.items() if "覆盖" in k]
    assert bound and bound[0]["binding_verified"] is True

    b2 = json.loads(json.dumps(b))
    b2["binding_epoch"]["prev_anchor_attestation"]["tsa_qualified"] = True
    r2 = verify_bundle(b2, ca)
    assert r2.ok, "改动合格判定不应让技术验证失败"
    bad = [v for k, v in r2.attestations.items() if "覆盖" in k or "绑定" in k]
    assert bad and bad[0].get("binding_verified") is not True, \
        "改动了被绑定的判定，绑定校验却仍然通过"


# ---------------------------------------------------------------------------
# 支撑件
# ---------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class _FakeAnchor:
    """只带 attach_anchor 用得到的字段。刻意不造真 token：

    这些测试要断言的是哈希与结构行为，与 token 内容无关。用真 token 会把
    一组纯逻辑测试绑到网络和证书有效期上。
    """
    epoch_id: int
    anchored_hash: str
    tsa_url: str = "http://tsa.example/x"
    token_b64: str | None = base64.b64encode(b"not-a-real-token").decode()
    tsa_qualified: bool | None = False
    eutl_ref: str | None = None
    qualified_checked_at: str | None = "2026-08-16T00:00:00+00:00"
    eutl_snapshot_sha256: str | None = "34" * 32

    def token_bytes(self) -> bytes:
        return base64.b64decode(self.token_b64) if self.token_b64 else b""


def _append(led: Ledger) -> None:
    from tg_attest import EvidenceRef, GateVerdict
    n = len(led._records)
    led.append(actor={"id": f"u{n}"}, model={"id": "m"}, inputs={"i": n},
               output={"o": str(n)},
               evidence=[EvidenceRef(source_id="s", as_of="2026-08-01T00:00:00+00:00",
                                     observed_at="2026-08-16T00:00:00+00:00",
                                     value_hash="ab" * 32)],
               gates=[GateVerdict(gate="g", verdict="pass")])


@pytest.fixture
def led_with_epoch():
    led = Ledger()
    _append(led)
    e0 = led.seal_epoch()
    return led, e0, e0.epoch_hash()


@pytest.fixture
def led_two_epochs():
    led = Ledger()
    _append(led)
    e0 = led.seal_epoch()
    before = e0.epoch_hash()
    a = _FakeAnchor(epoch_id=0, anchored_hash=before)
    led.attach_anchor(a)
    _append(led)
    led.seal_epoch()
    # token_sha256 必须与实际写回的 token 对得上，否则 verify 会先报那一条
    assert led._epochs[1].prev_anchor_attestation.token_sha256 == \
        hashlib.sha256(a.token_bytes()).hexdigest()
    return led
