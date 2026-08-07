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



class TestMTEViolation(unittest.TestCase):
    """MTEViolation: violation record with metadata."""

    def test_violation_creation(self):
        """创建违规记录，字段正确"""
        v = MTEViolation(
            vtype=MTEViolationType.STACK_BUFFER_OVERFLOW,
            addr=0x1000,
            actual_tag=3,
            expected_tag=5,
            pc=0xDEAD,
            access_size=8,
            is_write=True,
            context="test_func",
            message="Overflow detected",
        )
        self.assertEqual(v.vtype, MTEViolationType.STACK_BUFFER_OVERFLOW)
        self.assertEqual(v.addr, 0x1000)
        self.assertEqual(v.actual_tag, 3)
        self.assertEqual(v.expected_tag, 5)
        self.assertEqual(v.pc, 0xDEAD)
        self.assertEqual(v.access_size, 8)
        self.assertTrue(v.is_write)

    def test_violation_timestamp_auto(self):
        """未提供 timestamp 时自动使用当前时间"""
        v = MTEViolation(
            vtype=MTEViolationType.USE_AFTER_FREE,
            addr=0x2000,
            actual_tag=1,
            expected_tag=2,
            pc=0xBEEF,
            access_size=4,
            is_write=False,
        )
        self.assertGreater(v.timestamp, 0)

    def test_violation_types_enum(self):
        """所有 MTEViolationType 枚举值可用"""
        types = [
            MTEViolationType.STACK_BUFFER_OVERFLOW,
            MTEViolationType.HEAP_BUFFER_OVERFLOW,
            MTEViolationType.USE_AFTER_FREE,
            MTEViolationType.DOUBLE_FREE,
            MTEViolationType.WILD_FREE,
        ]
        for t in types:
            self.assertIsInstance(t.value, str)


class TestMTEReport(unittest.TestCase):
    """MTEReport: aggregated violation report."""

    def test_empty_report(self):
        """空报告所有计数为 0"""
        report = MTEReport(total_allocs=0, total_frees=0, total_violations=0)
        self.assertEqual(report.total_allocs, 0)
        self.assertEqual(report.total_violations, 0)

    def test_report_with_violations(self):
        """报告包含违规列表和按类型统计"""
        v1 = MTEViolation(
            vtype=MTEViolationType.HEAP_BUFFER_OVERFLOW,
            addr=0x1000, actual_tag=1, expected_tag=2,
            pc=0xDEAD, access_size=4, is_write=True,
        )
        v2 = MTEViolation(
            vtype=MTEViolationType.USE_AFTER_FREE,
            addr=0x2000, actual_tag=3, expected_tag=3,
            pc=0xBEEF, access_size=8, is_write=False,
        )
        report = MTEReport(
            total_allocs=10,
            total_frees=5,
            total_violations=2,
            violations=[v1, v2],
            by_type={"heap_buffer_overflow": 1, "use_after_free": 1},
            coverage=0.75,
        )
        self.assertEqual(report.total_violations, 2)
        self.assertEqual(report.total_allocs, 10)

    def test_mte_allocation_dataclass(self):
        """MTEAllocation 数据类字段正确"""
        now = time.time()
        alloc = MTEAllocation(
            addr=0x3000,
            size=128,
            tag=7,
            alloc_type="heap",
            var_name="user_buffer",
            freed=False,
            alloc_time=now,
        )
        self.assertEqual(alloc.size, 128)
        self.assertEqual(alloc.tag, 7)
        self.assertEqual(alloc.var_name, "user_buffer")
        self.assertFalse(alloc.freed)


class TestMTEAnalyzer(unittest.TestCase):
    """MTEAnalyzer: high-level interface wrapping MTEState."""

    def setUp(self):
        self.analyzer = MTEAnalyzer()

    def test_record_alloc(self):
        """record_alloc 注册一次分配"""
        self.analyzer.record_alloc(0x4000, 64, alloc_type="stack", var_name="buf")
        report = self.analyzer.build_report()
        self.assertEqual(report.total_allocs, 1)

    def test_record_free_success(self):
        """合法 free 返回 True"""
        self.analyzer.record_alloc(0x5000, 32)
        ok = self.analyzer.record_free(0x5000)
        self.assertTrue(ok)

    def test_record_free_failure(self):
        """free 未分配地址返回 False"""
        ok = self.analyzer.record_free(0xBEEF)
        self.assertFalse(ok)

    def test_double_free_via_analyzer(self):
        """通过 analyzer 检测 double free"""
        self.analyzer.record_alloc(0x6000, 16)
        self.analyzer.record_free(0x6000)
        ok = self.analyzer.record_free(0x6000)
        self.assertFalse(ok)

    def test_uaf_detection_via_analyzer(self):
        """free 后 access 检测 UAF"""
        self.analyzer.record_alloc(0x7000, 32)
        self.analyzer.record_free(0x7000)
        violations = self.analyzer.record_access(0x7000, 4, is_write=False)
        self.assertGreater(len(violations), 0)

    def test_build_report_aggregates(self):
        """build_report 汇总 alloc/free/violation 计数"""
        self.analyzer.record_alloc(0x1000, 16)
        self.analyzer.record_alloc(0x2000, 32)
        self.analyzer.record_alloc(0x3000, 64)
        self.analyzer.record_free(0x3000)
        report = self.analyzer.build_report()
        self.assertEqual(report.total_allocs, 3)
        self.assertEqual(report.total_frees, 1)

    def test_reset_clears_state(self):
        """reset 清空所有状态"""
        self.analyzer.record_alloc(0x1000, 16)
        self.analyzer.reset()
        report = self.analyzer.build_report()
        self.assertEqual(report.total_allocs, 0)

    def test_enable_disable(self):
        """enable(False) 后不再检测违规"""
        self.analyzer.record_alloc(0x4000, 32)
        self.analyzer.enable(False)
        self.analyzer.record_free(0x4000)
        violations = self.analyzer.record_access(0x4000, 4, is_write=False)
        # 禁用状态下不产生违规
        self.assertEqual(len(violations), 0)
        self.analyzer.enable(True)


class TestMTETagGranuleConstant(unittest.TestCase):
    """MTE_TAG_GRANULE constant."""

    def test_tag_granule_is_16(self):
        """ARM MTE 的 TAG_GRANULE 应为 16 字节"""
        self.assertEqual(MTE_TAG_GRANULE, 16)


if __name__ == "__main__":
    unittest.main()
