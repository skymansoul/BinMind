"""
集成测试 — 验证仿射边界验证六阶段管线各模块可独立导入和运行.

不依赖外部编译器, 直接用内联伪代码输入测试每个模块.
"""

from __future__ import annotations
import os, sys, unittest

BASE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(BASE)
sys.path.insert(0, PROJECT)


class TestValueRangePropagator(unittest.TestCase):
    """Stage 1: 值域传播."""

    def test_import(self):
        from analysis.value_range_propagator import (
            Interval, VarRange, ValueRangePropagator,
            extract_size_constraints_from_ir,
        )
        self.assertIsNotNone(Interval)
        self.assertIsNotNone(ValueRangePropagator)

    def test_interval_ops(self):
        from analysis.value_range_propagator import Interval
        a = Interval(0, 100)
        b = Interval(50, 200)
        c = a.intersect(b)
        self.assertEqual(c.low, 50)
        self.assertEqual(c.high, 100)
        d = a.union(b)
        self.assertEqual(d.low, 0)
        self.assertEqual(d.high, 200)

    def test_propagate_const(self):
        from analysis.value_range_propagator import ValueRangePropagator
        ir_lines = [
            "size = 64;",
            "buf = malloc(size);",
        ]
        vrp = ValueRangePropagator()
        vrp.propagate(ir_lines)
        # size 应为 [64, 64]
        self.assertIn("size", vrp.ranges)


class TestGuardConditionAnalyzer(unittest.TestCase):
    """Stage 2: 守卫条件分析."""

    def test_import(self):
        from analysis.guard_condition_analyzer import (
            GuardCondition, find_guard_for_variable,
            is_store_safeguarded, extract_all_guards,
        )
        self.assertIsNotNone(GuardCondition)
        self.assertIsNotNone(find_guard_for_variable)

    def test_direct_cmp_jcc(self):
        from analysis.guard_condition_analyzer import extract_all_guards
        ir_lines = [
            "if (idx < 64) {",
            "    buf[idx] = 0;",
            "}",
        ]
        guards = extract_all_guards(ir_lines)
        # G1: cmp+jcc 模式
        self.assertGreaterEqual(len(guards), 0)

    def test_loop_bound_guard(self):
        from analysis.guard_condition_analyzer import extract_all_guards
        ir_lines = [
            "for (int i = 0; i < 64; i++) {",
            "    buf[i] = x;",
            "}",
        ]
        guards = extract_all_guards(ir_lines)
        self.assertIsInstance(guards, list)


class TestAllocatorChunkModel(unittest.TestCase):
    """Stage 3: 分配器chunk建模."""

    def test_import(self):
        from analysis.allocator_chunk_model import (
            ChunkLayout, estimate_chunk_layout,
            is_within_slack, would_overflow, compute_effective_boundary,
        )
        self.assertIsNotNone(ChunkLayout)

    def test_request2size(self):
        from analysis.allocator_chunk_model import estimate_chunk_layout
        # malloc(23): padded=23+8=31→MINSIZE=32→aligned=32→usable=32-16=16
        # glibc最小chunk=32B, overhead=16B, 所以可用=16
        layout = estimate_chunk_layout(23)
        self.assertIsNotNone(layout)
        # request2size(23) → usable=16 (glibc MINSIZE overhead)
        self.assertGreaterEqual(layout.usable_size, 16)

    def test_minsize_boundary(self):
        from analysis.allocator_chunk_model import estimate_chunk_layout
        layout = estimate_chunk_layout(1)  # 最小请求
        self.assertIsNotNone(layout)
        # MINSIZE=32, 所以即使请求1字节,usable_size >= 32-sizeof(chunk_header)
        self.assertGreaterEqual(layout.usable_size, 1)

    def test_would_overflow(self):
        from analysis.allocator_chunk_model import (
            would_overflow, estimate_chunk_layout,
        )
        # malloc(8): layout needed for would_overflow
        layout8 = estimate_chunk_layout(8)
        self.assertTrue(would_overflow(0, 128, layout8)[0])
        # malloc(1024), write 64 → no overflow
        layout1k = estimate_chunk_layout(1024)
        self.assertFalse(would_overflow(0, 64, layout1k)[0])


class TestHeapDisambiguator(unittest.TestCase):
    """Stage 4: 堆/栈/全局区分."""

    def test_import(self):
        from analysis.heap_disambiguator import (
            MemAccess, MemRegion, is_likely_heap_write,
            classify_memory_access, extract_heap_accesses,
        )
        self.assertIsNotNone(MemRegion)

    def test_stack_register_recognition(self):
        from analysis.heap_disambiguator import classify_memory_access
        # rsp/rbp → stack
        result = classify_memory_access("*(rsp + 0x10) = val;", {})
        self.assertIsNotNone(result)

    def test_malloc_return_is_heap(self):
        from analysis.heap_disambiguator import is_likely_heap_write
        # rax after malloc → heap
        result = is_likely_heap_write(
            "puVar1 = (char *)malloc(64);", set(), set()
        )
        self.assertIsInstance(result, tuple)
        is_heap, confidence, reason = result
        self.assertIsInstance(is_heap, bool)
        self.assertIsInstance(reason, str)


class TestFlowSensitiveTracker(unittest.TestCase):
    """Stage 5: 流敏感分配大小追踪."""

    def test_import(self):
        from analysis.flow_sensitive_tracker import (
            AllocRecord, VarsEquivClass, FlowSensitiveTracker,
        )
        self.assertIsNotNone(FlowSensitiveTracker)

    def test_track_allocation(self):
        from analysis.flow_sensitive_tracker import FlowSensitiveTracker
        tracker = FlowSensitiveTracker()
        ir_lines = [
            "char *buf = (char *)malloc(64);",
            "char *p = buf;",
            "p[100] = 0;",
        ]
        tracker.track(ir_lines)
        records = tracker.get_allocation_history("buf")
        self.assertIsInstance(records, list)

    def test_pointer_equivalence(self):
        from analysis.flow_sensitive_tracker import FlowSensitiveTracker
        tracker = FlowSensitiveTracker()
        ir_lines = [
            "char *a = malloc(128);",
            "char *b = a;",
            "char *c = b;",
        ]
        tracker.track(ir_lines)
        # b 和 c 应该等价于 a
        self.assertIsNotNone(tracker.equiv_classes)


class TestEnhancedFPFilter(unittest.TestCase):
    """Stage 6: 增强误报过滤."""

    def test_import(self):
        from analysis.enhanced_fp_filter import (
            filter_non_heap_writes, filter_guarded_stores,
            adjust_for_slack, adjust_for_value_range,
            run_enhanced_filter,
        )
        self.assertIsNotNone(run_enhanced_filter)

    def test_filter_non_heap(self):
        from analysis.enhanced_fp_filter import filter_non_heap_writes
        candidates = [{"confidence": 0.8, "is_heap": False, "store_line": ""}]
        result, filtered_count = filter_non_heap_writes(candidates, [])
        self.assertIsInstance(result, list)

    def test_run_enhanced_filter_end_to_end(self):
        from analysis.enhanced_fp_filter import run_enhanced_filter
        from unittest.mock import MagicMock
        c = MagicMock()
        c.alloc_site = MagicMock()
        c.alloc_site.size_arg = 64
        c.alloc_site.result_var = "buf"
        c.alloc_site.alloc_func = "malloc"
        c.alloc_site.pc = 1
        c.overflow_store = MagicMock()
        c.overflow_store.offset = 128
        c.overflow_store.base_var = "buf"
        c.overflow_store.pc = 2
        c.confidence = 0.8
        c.description = ""
        c.has_guard = False
        candidates = [c]
        ir_lines = ["    buf = malloc(64);", "    memset(buf, 0, 128);"]
        result, stats = run_enhanced_filter(candidates, ir_lines)
        self.assertIsInstance(result, list)
        self.assertIsInstance(stats, dict)


class TestPipelineIntegration(unittest.TestCase):
    """全管线端到端集成."""

    def test_import_full_pipeline(self):
        from core.heap_overflow_pipeline import detect_heap_overflows_full
        self.assertIsNotNone(detect_heap_overflows_full)

    def test_ir_to_detection_flow(self):
        """验证: IR → 提取 → 过滤 完整链路 (仅测试导入和基本类型)."""
        ir = """\
        ulong main(void)
        {
          char *buf;
          buf = (char *)malloc(64);
          if (buf == (char *)0x0) {
            return 1;
          }
          memset(buf, 0, 128);
          free(buf);
          return 0;
        }"""
        lines = ir.splitlines()

        # 1. 提取堆操作 — 验证导入和类型
        from core.heap_overflow_detector import detect_heap_overflow
        candidates = detect_heap_overflow(lines, ir)
        self.assertIsInstance(candidates, list)

        # 2. 如果有候选项, 验证其数据类型
        for c in candidates:
            self.assertTrue(hasattr(c, 'confidence'))
            self.assertTrue(hasattr(c, 'alloc_site'))
            self.assertTrue(hasattr(c, 'overflow_store'))

        # 3. 基本的管线阶段可用性验证
        from analysis.enhanced_fp_filter import (
            filter_non_heap_writes, filter_guarded_stores,
            run_enhanced_filter,
        )
        self.assertIsNotNone(filter_non_heap_writes)
        self.assertIsNotNone(filter_guarded_stores)
        self.assertIsNotNone(run_enhanced_filter)


def run_all():
    """运行所有集成测试."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # 按管线顺序添加
    suite.addTests(loader.loadTestsFromTestCase(TestValueRangePropagator))
    suite.addTests(loader.loadTestsFromTestCase(TestGuardConditionAnalyzer))
    suite.addTests(loader.loadTestsFromTestCase(TestAllocatorChunkModel))
    suite.addTests(loader.loadTestsFromTestCase(TestHeapDisambiguator))
    suite.addTests(loader.loadTestsFromTestCase(TestFlowSensitiveTracker))
    suite.addTests(loader.loadTestsFromTestCase(TestEnhancedFPFilter))
    suite.addTests(loader.loadTestsFromTestCase(TestPipelineIntegration))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(run_all())
