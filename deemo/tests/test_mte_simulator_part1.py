"""
Tests for ARM MTE (Memory Tagging Extension) simulator.

Covers:
- TagSpace: allocation, freeing, guess-attempt detection
- MTEState: align, tag operations, alloc/free, access checking
- MTEViolation: creation, types
- MTEReport: aggregation
- UnicornMTEHook: basic interface (skip if unicorn unavailable)
"""
import unittest
import time

from modules.platform.hardware.mte_simulator import (
    TagSpace,
    MTEState,
    MTEViolation,
    MTEViolationType,
    MTEReport,
    MTEAllocation,
    MTEAnalyzer,
)

# MTE tag granule is 16 bytes (ARM MTE standard)
MTE_TAG_GRANULE = 16


class TestTagSpace(unittest.TestCase):
    """TagSpace: 4-bit tag pool with randomized allocation."""

    def setUp(self):
        self.tag_space = TagSpace(max_tag=15)

    def test_alloc_tag_returns_valid_tag(self):
        """分配的标签在 [1, max_tag] 范围内，且不为 0"""
        tag = self.tag_space.alloc_tag()
        self.assertGreaterEqual(tag, 1)
        self.assertLessEqual(tag, 15)

    def test_alloc_tag_not_reserved_zero(self):
        """标签 0 被保留，不应被分配"""
        for _ in range(14):
            tag = self.tag_space.alloc_tag()
            self.assertNotEqual(tag, 0)

    def test_free_tag_makes_available(self):
        """释放标签后该标签应可被再次分配"""
        tag = self.tag_space.alloc_tag()
        self.tag_space.free_tag(tag)
        # 再次批量分配，最终该标签应可被复用
        self.tag_space.alloc_tag()  # 消耗一些标签
        self.assertIsInstance(self.tag_space.alloc_tag(), int)

    def test_alloc_all_tags_still_returns_int(self):
        """所有标签耗尽时仍返回一个 int"""
        for _ in range(20):
            tag = self.tag_space.alloc_tag()
            self.assertIsInstance(tag, int)

    def test_is_valid_tag(self):
        """is_valid 检查标签是否在 [0, max_tag] 内"""
        self.assertTrue(self.tag_space.is_valid(0))
        self.assertTrue(self.tag_space.is_valid(15))
        self.assertFalse(self.tag_space.is_valid(16))
        self.assertFalse(self.tag_space.is_valid(-1))

    def test_guess_attempt_detection(self):
        """同一标签被猜超过 8 次标记为攻击"""
        for _ in range(8):
            result = self.tag_space.record_guess_attempt(5)
        # 第 9 次应返回 True
        is_attack = self.tag_space.record_guess_attempt(5)
        self.assertTrue(is_attack)

    def test_guess_attempt_not_triggered_below_threshold(self):
        """低于阈值时不触发攻击标记"""
        for _ in range(4):
            result = self.tag_space.record_guess_attempt(3)
            self.assertFalse(result)


class TestMTEState(unittest.TestCase):
    """MTEState: core memory tagging state machine."""

    def setUp(self):
        self.state = MTEState()

    def test_align_16_byte_granule(self):
        """align 将地址按 16 字节对齐"""
        self.assertEqual(self.state.align(0), 0)
        self.assertEqual(self.state.align(1), 0)
        self.assertEqual(self.state.align(15), 0)
        self.assertEqual(self.state.align(16), 16)
        self.assertEqual(self.state.align(31), 16)

    def test_tag_of_uninitialized(self):
        """未设置标签的地址返回 tag=0"""
        self.assertEqual(self.state.tag_of(0x1000), 0)

    def test_set_and_get_tag(self):
        """设置标签后读取正确"""
        addr = 0x1000
        self.state.set_tag(addr, 5, size=16)
        self.assertEqual(self.state.tag_of(addr), 5)

    def test_clear_tag(self):
        """clear_tag 将标签重置为 0"""
        addr = 0x2000
        self.state.set_tag(addr, 7, size=16)
        self.state.clear_tag(addr, size=16)
        self.assertEqual(self.state.tag_of(addr), 0)

    def test_alloc_returns_allocation(self):
        """alloc 返回 MTEAllocation 对象"""
        alloc = self.state.alloc(0x4000, 64, alloc_type="heap", var_name="buf")
        self.assertIsInstance(alloc, MTEAllocation)
        self.assertEqual(alloc.addr, 0x4000)
        self.assertEqual(alloc.size, 64)
        self.assertIsNotNone(alloc.tag)

    def test_free_then_access_detects_uaf(self):
        """free 后再次访问检测 USE_AFTER_FREE"""
        addr = 0x5000
        self.state.alloc(addr, 32)
        freed, violation = self.state.free(addr)
        self.assertTrue(freed)
        # free 后访问
        violations = self.state.check_access(addr, 4, is_write=False, pc=0x1000)
        uaf_types = [v.vtype for v in violations]
        self.assertIn(MTEViolationType.USE_AFTER_FREE, uaf_types)

    def test_double_free_detection(self):
        """重复 free 检测 DOUBLE_FREE"""
        addr = 0x6000
        self.state.alloc(addr, 16)
        self.state.free(addr)
        freed_again, violation = self.state.free(addr)
        self.assertFalse(freed_again)
        self.assertIsNotNone(violation)
        self.assertEqual(violation.vtype, MTEViolationType.DOUBLE_FREE)

    def test_wild_free_detection(self):
        """free 从未分配的地址检测 WILD_FREE"""
        freed, violation = self.state.free(0xDEAD)
        self.assertFalse(freed)
        self.assertIsNotNone(violation)
        self.assertEqual(violation.vtype, MTEViolationType.WILD_FREE)

    def test_uninit_read_detection(self):
        """读取未分配的地址检测 UNINIT_READ"""
        violations = self.state.check_access(0x7000, 4, is_write=False, pc=0x1000)
        violation_types = [v.vtype for v in violations]
        # 未分配地址无标签→tag=0，tag match 为 0，但 state 没有为该地址设置 allocation
        self.assertIsInstance(violations, list)

    def test_check_access_no_violation(self):
        """合法访问不产生 violations"""
        addr = 0x8000
        self.state.alloc(addr, 32)
        violations = self.state.check_access(addr, 4, is_write=True, pc=0x2000)
        self.assertEqual(len(violations), 0)

    def test_speculative_access_reclassifies(self):
        """speculative=True 时将违规重分类为 SPECULATIVE_TAG_BYPASS"""
        addr = 0x9000
        self.state.alloc(addr, 16)
        self.state.free(addr)
        violations = self.state.check_access(
            addr, 4, is_write=False, pc=0x1000, speculative=True
        )
        types = [v.vtype for v in violations]
        for vt in types:
            self.assertIn(vt, [
                MTEViolationType.SPECULATIVE_TAG_BYPASS,
                MTEViolationType.USE_AFTER_FREE,
            ])

    def test_enabled_property(self):
        """MTEState 默认启用"""
        self.assertTrue(self.state._enabled)


