"""不变量：同一个对象，在任何机器、任何进程、任何插入顺序下，
序列化出的字节完全相同。

这条不成立，整条哈希链在审计时全线报废——而且是静默报废：
链自洽，只是和三个月前那台机器算出来的对不上，没人能说清哪边是对的。
哈希链最常见的失败点不是密码学，是序列化不确定。
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from tg_attest.record import canonical_bytes, hash_obj

# --- 键排序 ---------------------------------------------------------------

def test_key_order_does_not_affect_bytes():
    """插入顺序不同，字节必须相同。dict 在 Python 里是有序的，
    所以这不是自动成立的——不 sort_keys 就会挂。"""
    a = {"z": 1, "a": 2, "m": 3}
    b = {"a": 2, "m": 3, "z": 1}
    assert canonical_bytes(a) == canonical_bytes(b)
    assert canonical_bytes(a) == b'{"a":2,"m":3,"z":1}'


def test_nested_keys_are_sorted_too():
    inner_first = {"outer": {"z": 1, "a": 2}, "b": 3}
    inner_last = {"b": 3, "outer": {"a": 2, "z": 1}}
    assert canonical_bytes(inner_first) == canonical_bytes(inner_last)
    assert canonical_bytes(inner_first) == b'{"b":3,"outer":{"a":2,"z":1}}'


def test_keys_sort_by_code_point_not_locale():
    """按 Unicode 码点排，不按 locale。大写字母码点小于小写。"""
    assert canonical_bytes({"a": 1, "B": 2}) == b'{"B":2,"a":1}'


# --- 拒绝 float -----------------------------------------------------------

@pytest.mark.parametrize("obj", [
    1.5,
    {"amount": 1.5},
    {"nested": {"deep": {"x": 0.1}}},
    [1, 2, 3.0],
    {"list": [{"inner": 2.5}]},
    float("nan"),
    float("inf"),
    1e308,
])
def test_float_is_rejected(obj):
    """IEEE754 的文本表示跨语言不一致。0.1 在 Python 里是
    '0.1'，在别的运行时可能是 '0.1000000000000000055511151231257827'。
    这是硬性拒绝，不是警告——警告会被忽略，然后在审计当天变成事故。"""
    with pytest.raises(TypeError, match="float"):
        canonical_bytes(obj)


def test_float_error_names_the_path():
    """错误信息要指出是哪个字段，否则在嵌套结构里没法查。"""
    with pytest.raises(TypeError, match=r"\$\.a\.b\[1\]"):
        canonical_bytes({"a": {"b": [1, 2.5]}})


def test_int_is_fine_and_bool_is_not_int():
    assert canonical_bytes({"n": 12345678901234567890}) == b'{"n":12345678901234567890}'
    assert canonical_bytes({"x": True}) == b'{"x":true}'
    assert canonical_bytes({"x": 1}) != canonical_bytes({"x": True})


def test_money_as_string_survives():
    """金额的正确写法：字符串保留精度，或整数最小单位。"""
    assert canonical_bytes({"amount": "12.3400"}) == b'{"amount":"12.3400"}'
    assert canonical_bytes({"amount_cents": 1234}) == b'{"amount_cents":1234}'


def test_non_string_key_is_rejected():
    with pytest.raises(TypeError, match="key"):
        canonical_bytes({1: "a"})


# --- 编码 -----------------------------------------------------------------

def test_no_whitespace():
    assert b" " not in canonical_bytes({"a": 1, "b": [1, 2]})


def test_utf8_not_escaped():
    """ensure_ascii=False：中文原样出，不转成 \\uXXXX。
    两种写法都是合法 JSON，但字节不同，所以必须钉死一种。"""
    out = canonical_bytes({"名称": "决策"})
    assert out == '{"名称":"决策"}'.encode()
    assert b"\\u" not in out


def test_empty_containers():
    assert canonical_bytes({}) == b"{}"
    assert canonical_bytes([]) == b"[]"
    assert canonical_bytes({"a": {}, "b": []}) == b'{"a":{},"b":[]}'


# --- 跨进程 ---------------------------------------------------------------

_CHILD = """
import json, sys
from tg_attest.record import canonical_bytes
obj = json.loads(sys.argv[1])
sys.stdout.write(canonical_bytes(obj).hex())
"""


@pytest.mark.parametrize("seed", ["0", "1", "12345", "random"])
def test_same_bytes_across_processes(seed):
    """不同 PYTHONHASHSEED 下的独立进程必须给出相同字节。

    PYTHONHASHSEED 会改变 str 的哈希，进而改变 dict 的内部布局。
    如果实现里有任何一处依赖了 dict 的遍历顺序而不是显式排序，
    这个用例会抓到它——而单进程内的测试永远抓不到。
    """
    obj = {"z": "值", "a": [{"m": 1, "b": "2"}], "k": None, "nested": {"y": 1, "x": 2}}
    payload = json.dumps(obj)
    outs = {
        subprocess.run(
            [sys.executable, "-c", _CHILD, payload],
            capture_output=True, text=True, check=True,
            env={"PYTHONHASHSEED": seed, "PATH": "/usr/bin:/bin"},
        ).stdout
        for _ in range(3)
    }
    assert len(outs) == 1
    assert bytes.fromhex(outs.pop()) == canonical_bytes(obj)


# --- 哈希 -----------------------------------------------------------------

def test_hash_obj_is_sha256_of_canonical_bytes():
    import hashlib
    obj = {"b": 2, "a": 1}
    assert hash_obj(obj) == hashlib.sha256(b'{"a":1,"b":2}').hexdigest()


def test_distinct_objects_hash_differently():
    assert hash_obj({"a": 1}) != hash_obj({"a": "1"})
    assert hash_obj({"a": 1}) != hash_obj({"a": 1, "b": None})
    assert hash_obj([1, 2]) != hash_obj([2, 1])
