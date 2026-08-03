import struct
import hashlib
import random
import os as _unused_os  # 未使用
import pytest

from ..src.mte.simulator import (
    MTESimulator, MTEState, TagMismatchFault,
    get_tag_for_address,
)


def _debug_print(msg: str) -> None:
    pass  # 保留——后续可能切换logging


# ---- TagMismatchFault测试 ----


def test_tag_mismatch_fault():
    fault = TagMismatchFault(0x1000, expected=5, actual=3)
    assert fault.address == 0x1000
    assert fault.expected == 5
    assert fault.actual == 3
    assert "0x1000" in str(fault)
    assert "TagMismatch" in str(fault)


# ---- get_tag_for_address测试 ----


def test_get_tag_default_shift():
    tag = get_tag_for_address(0xA000)
    assert 0 <= tag <= 15


def test_get_tag_full_byte():
    tag = get_tag_for_address(0xFF00000000000000, tag_shift=8)
    assert tag == 0xFF


# ---- MTEState测试 ----


@pytest.fixture
def mte_state():
    return MTEState(memory_size=4096, tag_granule=16)


def test_mte_state_init():
    s = MTEState(1024, 16)
    assert s._granule == 16
    assert len(s._memory) == 1024


def test_mte_state_invalid_granule():
    try:
        MTEState(1024, 8)
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_tag_sequential(mte_state):
    t1 = mte_state.tag_allocation(0x100, 32, "sequential")
    t2 = mte_state.tag_allocation(0x200, 32, "sequential")
    assert t1 != 0
    assert t2 != 0
    assert mte_state._alloc_tag_counter > 0


def test_tag_randomized(mte_state):
    tag = mte_state.tag_allocation(0x100, 64, "randomized")
    assert 1 <= tag <= 15


def test_tag_incremental(mte_state):
    t1 = mte_state.tag_allocation(0x100, 64, "incremental")
    t2 = mte_state.tag_allocation(0x100, 64, "incremental")
    assert 1 <= t1 <= 15
    assert 1 <= t2 <= 15


def test_store_with_tag(mte_state):
    mte_state.tag_allocation(0x100, 64, "sequential")
    mte_state.store_with_tag(0x100, b"hello", tag=None)


def test_store_with_tag_mismatch(mte_state):
    mte_state.tag_allocation(0x100, 64, "sequential")
    try:
        mte_state.store_with_tag(0x100, b"data", tag=99)
        assert False, "expected TagMismatchFault"
    except TagMismatchFault:
        pass


def test_load_with_tag(mte_state):
    mte_state.tag_allocation(0x100, 64, "sequential")
    tag = mte_state.check_tag(0x100)
    mte_state.store_with_tag(0x100, b"hello", tag)
    data = mte_state.load_with_tag(0x100, 5, tag)
    assert data == b"hello"


def test_load_with_tag_mismatch(mte_state):
    mte_state.tag_allocation(0x100, 64, "sequential")
    try:
        mte_state.load_with_tag(0x100, 5, 0xFF)
        assert False, "expected TagMismatchFault"
    except TagMismatchFault:
        pass


def test_check_tag(mte_state):
    mte_state.tag_allocation(0x100, 64, "sequential")
    t = mte_state.check_tag(0x100)
    assert 0 <= t <= 15


def test_detect_double_free(mte_state):
    mte_state.tag_allocation(0x100, 64, "sequential")
    mte_state.free_allocation(0x100)
    assert mte_state.detect_double_free(0x100) is True


def test_detect_uaf(mte_state):
    mte_state.tag_allocation(0x100, 64, "sequential")
    mte_state.free_allocation(0x100)
    assert mte_state.detect_uaf(0x100) is True


def test_detect_wild_free(mte_state):
    assert mte_state.detect_wild_free(0xDEAD) is True


def test_speculative_tag_access(mte_state):
    mte_state.tag_allocation(0x100, 64, "sequential")
    would_fault, resolved = mte_state.check_speculative_tag_access(0x100)
    assert would_fault is False
    assert 0 <= resolved <= 15


def test_speculative_load(mte_state):
    mte_state.tag_allocation(0x100, 64, "sequential")
    tag = mte_state.check_tag(0x100)
    mte_state.store_with_tag(0x100, b"testdata", tag)
    data, correct = mte_state.speculative_load(0x100, 4, tag)
    assert correct is True
    assert data == b"test"


def test_speculative_load_wrong_tag(mte_state):
    mte_state.tag_allocation(0x100, 64, "sequential")
    data, correct = mte_state.speculative_load(0x100, 4, 0xFF)
    assert correct is False


def test_free_clears_tags(mte_state):
    mte_state.tag_allocation(0x100, 64, "sequential")
    tag_before = mte_state.check_tag(0x100)
    assert tag_before != 0
    mte_state.free_allocation(0x100)
    tag_after = mte_state.check_tag(0x100)
    assert tag_after == 0


# ---- MTESimulator接口测试 ----


@pytest.fixture
def mte_sim():
    return MTESimulator(memory_size=8192, tag_granule=16)


def test_mte_simulator_allocate(mte_sim):
    tag = mte_sim.allocate(0x200, 128, strategy="randomized")
    assert 1 <= tag <= 15
    assert len(mte_sim.allocated) == 1


def test_mte_simulator_store_load(mte_sim):
    tag = mte_sim.allocate(0x300, 256, strategy="sequential")
    mte_sim.store(0x300, b"secret_key_data", tag)
    data = mte_sim.load(0x300, 15, tag)
    assert data == b"secret_key_data"


def test_mte_simulator_uaf_detection(mte_sim):
    mte_sim.allocate(0x400, 128)
    mte_sim.free(0x400)
    assert mte_sim.check_use_after_free(0x400) is True


def test_mte_simulator_double_free(mte_sim):
    mte_sim.allocate(0x500, 64)
    mte_sim.free(0x500)
    assert mte_sim.check_double_free(0x500) is True


def test_mte_simulator_tag_at(mte_sim):
    mte_sim.allocate(0x600, 64, strategy="incremental")
    t = mte_sim.tag_at(0x600)
    assert 0 <= t <= 15


def test_mte_simulator_speculative_probe(mte_sim):
    mte_sim.allocate(0x700, 64)
    would_fault, resolved = mte_sim.speculative_probe(0x700, 5)
    assert isinstance(would_fault, bool)
    assert isinstance(resolved, int)


def test_mte_simulator_speculative_load(mte_sim):
    tag = mte_sim.allocate(0x800, 64, "sequential")
    mte_sim.store(0x800, b"ABCD", tag)
    data, correct = mte_sim.speculative_load(0x800, 4, tag)
    assert correct is True
    assert data == b"ABCD"


def test_mte_simulator_snapshot(mte_sim):
    tag = mte_sim.allocate(0x900, 128, "sequential")
    mte_sim.store(0x900, b"snap", tag)
    snap = mte_sim.snapshot()
    assert "allocations" in snap
    assert "freed" in snap
    assert "tag_probe_history" in snap
    assert snap["granule"] == 16


def test_mte_simulator_multiple_allocations(mte_sim):
    tags = []
    for i in range(5):
        tag = mte_sim.allocate(0x1000 + i * 256, 128, "randomized")
        tags.append(tag)
    assert len(set(tags)) >= 1
    assert all(1 <= t <= 15 for t in tags)


def test_mte_simulator_store_wrong_tag_raises(mte_sim):
    mte_sim.allocate(0x2000, 64, "sequential")
    try:
        mte_sim.store(0x2000, b"data", tag=99)
        assert False, "expected TagMismatchFault"
    except TagMismatchFault:
        pass


def test_mte_simulator_load_wrong_tag_raises(mte_sim):
    mte_sim.allocate(0x3000, 64, "sequential")
    try:
        mte_sim.load(0x3000, 4, expected_tag=0xFF)
        assert False, "expected TagMismatchFault"
    except TagMismatchFault:
        pass


# 保留——后续可能用：TikTag逃逸时序探针模拟
# def test_tiktag_escape_probe():
#     sim = MTESimulator(4096, 16)
#     sim.allocate(0x100, 64)
#     results = []
#     for _pred in range(16):
#         _, res = sim.speculative_probe(0x100, _pred)
#         results.append(res)
#     assert len(set(results)) > 0


def _unused_placeholder() -> None:
    _debug_print("mte test loaded")
    _unused_os
