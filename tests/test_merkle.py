"""不变量：包含证明只能证明真实存在的那一条。

Merkle 在这里不是镀金，是刚需。监管问的是一笔贷款、一笔理赔、一笔交易，
纯哈希链要证明「第 47 条没被改过」就得把整条链交出去。
包含证明让你只出示一条，代价是 O(log n) 的证明路径。

所以三件事必须同时成立，缺一条整个选择性披露就是假的：
    真实记录 + 自己的证明  → 通过
    伪造记录 + 自己的证明  → 拒绝
    真实记录 + 别人的证明  → 拒绝
"""

from __future__ import annotations

import hashlib
import math

import pytest

from tg_attest.record import (
    GENESIS,
    _leaf,
    _node,
    inclusion_proof,
    merkle_root,
    verify_inclusion,
)

MAX_N = 64


def leaves(n: int, salt: str = "") -> list[str]:
    return [hashlib.sha256(f"{salt}rec-{i}".encode()).hexdigest() for i in range(n)]


# --- 正向：n=1..64 的每一个位置都要能自证 --------------------------------

@pytest.mark.parametrize("n", range(1, MAX_N + 1))
def test_every_position_proves_itself(n):
    hs = leaves(n)
    root = merkle_root(hs)
    for i in range(n):
        proof = inclusion_proof(hs, i)
        assert verify_inclusion(hs[i], proof, root), f"n={n} index={i} 自证失败"


# --- 反向 1：伪造的记录哈希必须被拒 --------------------------------------

@pytest.mark.parametrize("n", range(1, MAX_N + 1))
def test_forged_hash_is_rejected(n):
    """拿真实的证明路径去证一条伪造的记录。这是最直接的攻击：
    改了内容、算出新哈希，还想沿用原来的证明。"""
    hs = leaves(n)
    root = merkle_root(hs)
    forged = hashlib.sha256(b"forged").hexdigest()
    for i in range(n):
        proof = inclusion_proof(hs, i)
        assert not verify_inclusion(forged, proof, root), f"n={n} index={i} 放行了伪造哈希"


# --- 反向 2：用别人的证明必须被拒 ----------------------------------------

@pytest.mark.parametrize("n", range(2, MAX_N + 1))
def test_proof_of_another_leaf_is_rejected(n):
    """把 j 的证明套到 i 上。证明路径不带位置字段，位置是由
    (side, sibling) 序列隐含的——所以这条如果不成立，说明侧向信息没起作用。"""
    hs = leaves(n)
    root = merkle_root(hs)
    bad = 0
    for i in range(n):
        for j in range(n):
            if i == j:
                continue
            if verify_inclusion(hs[i], inclusion_proof(hs, j), root):
                bad += 1
    assert bad == 0, f"n={n}：有 {bad} 组交叉证明被错误放行"


# --- 反向 3：换一棵树的根必须被拒 ----------------------------------------

@pytest.mark.parametrize("n", range(1, MAX_N + 1))
def test_proof_against_foreign_root_is_rejected(n):
    hs, other = leaves(n), leaves(n, salt="other-")
    other_root = merkle_root(other)
    for i in range(n):
        assert not verify_inclusion(hs[i], inclusion_proof(hs, i), other_root)


# --- 根对内容的敏感性 -----------------------------------------------------

@pytest.mark.parametrize("n", range(2, 17))
def test_changing_any_leaf_changes_the_root(n):
    hs = leaves(n)
    root = merkle_root(hs)
    for i in range(n):
        m = list(hs)
        m[i] = hashlib.sha256(f"changed-{i}".encode()).hexdigest()
        assert merkle_root(m) != root, f"n={n}：改第 {i} 片叶子，根没变"


@pytest.mark.parametrize("n", range(2, 17))
def test_reordering_changes_the_root(n):
    hs = leaves(n)
    swapped = list(hs)
    swapped[0], swapped[-1] = swapped[-1], swapped[0]
    assert merkle_root(swapped) != merkle_root(hs)


def test_truncation_changes_the_root():
    """删掉末尾若干条，根必须变。删记录是最省事的篡改方式。"""
    hs = leaves(16)
    root = merkle_root(hs)
    for k in range(1, 16):
        assert merkle_root(hs[:-k]) != root


# --- 结构性质 -------------------------------------------------------------

def test_empty_tree_is_genesis():
    assert merkle_root([]) == GENESIS


def test_single_leaf_root_is_the_prefixed_leaf_hash():
    """n=1 的根是 leaf(h)，不是 h 本身。

    这就是域分离：叶子前缀 0x00、内部节点前缀 0x01。不做域分离的话，
    一个内部节点的值可以被冒充成一片叶子，树的形状就可以被重新解释。
    """
    h = leaves(1)[0]
    assert merkle_root([h]) == _leaf(h)
    assert merkle_root([h]) != h


def test_leaf_and_node_hashes_never_collide():
    a, b = leaves(2)
    assert _leaf(a) != _node(a, b)
    assert _node(a, b) != _node(b, a)


@pytest.mark.parametrize("n", range(1, MAX_N + 1))
def test_proof_length_is_logarithmic(n):
    """证明长度的上界。这条是选择性披露的成本承诺：
    n=1000 条记录，出示一条只需要 10 层兄弟节点，不是 1000 条。"""
    hs = leaves(n)
    bound = math.ceil(math.log2(n)) if n > 1 else 0
    for i in range(n):
        assert len(inclusion_proof(hs, i)) <= bound


@pytest.mark.parametrize("n", range(1, 9))
def test_index_out_of_range_raises(n):
    hs = leaves(n)
    for bad in (-1, n, n + 1):
        with pytest.raises(IndexError):
            inclusion_proof(hs, bad)


def test_root_is_deterministic():
    hs = leaves(37)
    assert merkle_root(hs) == merkle_root(list(hs))


@pytest.mark.parametrize("n", range(1, MAX_N + 1))
def test_different_sizes_give_different_roots(n):
    """不同长度的列表不能算出同一个根，否则可以谎报记录条数。"""
    roots = {merkle_root(leaves(k)) for k in range(1, n + 1)}
    assert len(roots) == n


def test_tampered_proof_sibling_is_rejected():
    hs = leaves(8)
    root = merkle_root(hs)
    proof = inclusion_proof(hs, 3)
    for k in range(len(proof)):
        bad = list(proof)
        bad[k] = (bad[k][0], hashlib.sha256(b"nope").hexdigest())
        assert not verify_inclusion(hs[3], bad, root)


def test_flipped_side_is_rejected():
    """把 L/R 方向翻过来必须失败——方向参与哈希顺序。"""
    hs = leaves(8)
    root = merkle_root(hs)
    proof = inclusion_proof(hs, 3)
    flipped = [("R" if s == "L" else "L", h) for s, h in proof]
    assert not verify_inclusion(hs[3], flipped, root)
