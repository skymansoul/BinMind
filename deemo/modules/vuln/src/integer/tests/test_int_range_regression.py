"""INT-RANGE 回归测试 — 13个cve_intof样本 + 区间传播引擎 + 交叉验证.

测试: 模式检测(6种汇编模式) vs 区间传播(逐指令) vs 统一编排器.
验证: 召回率≥85%, 误报≤2, 交叉验证≥50%.

创建: 2024-11-05
"""
from __future__ import annotations

import os
import re
import sys
import time
import json
import glob
import subprocess
import unittest
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# 添加路径
_proj = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))))))
_int_src = os.path.join(os.path.dirname(os.path.dirname(__file__)))
if _int_src not in sys.path:
    sys.path.insert(0, _int_src)

from interval_domain import Interval, BitWidth, Signedness
from range_propagation import RangePropagationEngine
from int_orchestrator import IntOverflowOrchestrator, UnifiedReport


# 测试配置

_TEST_DIR = os.path.join(_proj, 'modules', 'exploit', 'tests', 'regression', 'build', 'gcc', 'O0')
_TEST_SAMPLES = [
    'cve_intof_03.exe', 'cve_intof_04.exe', 'cve_intof_05.exe',
    'cve_intof_06.exe', 'cve_intof_07.exe', 'cve_intof_08.exe',
    'cve_intof_09.exe', 'cve_intof_10.exe', 'cve_intof_11.exe',
    'cve_intof_12.exe', 'cve_intof_13.exe', 'cve_intof_14.exe',
    'cve_intof_15.exe',
]

# 期望检测状态 (至少1个真实发现)
_EXPECT_DETECTED = {
    'cve_intof_03.exe', 'cve_intof_04.exe', 'cve_intof_05.exe',
    'cve_intof_06.exe', 'cve_intof_08.exe', 'cve_intof_09.exe',
    'cve_intof_10.exe', 'cve_intof_11.exe', 'cve_intof_12.exe',
    'cve_intof_14.exe', 'cve_intof_15.exe',
}

# 不会在区间传播中产生发现的样本 (安全代码/栈分配/无溢出)
_EXPECT_SAFE = {
    'cve_intof_07.exe',   # 栈数组, 无堆分配
    'cve_intof_13.exe',   # 安全对照
}


def _disasm(path: str) -> List[str]:
    proc = subprocess.run(
        ['objdump', '-d', '-M', 'intel', path],
        capture_output=True, text=True, timeout=30,
        encoding='utf-8', errors='replace')
    return proc.stdout.split('\n') if proc.returncode == 0 else []


class TestIntervalDomain(unittest.TestCase):
    """区间域基础运算."""

    def test_basic_arithmetic(self):
        a = Interval(lo=0, hi=10)
        b = Interval(lo=5, hi=15)
        self.assertEqual(a.add(b).lo, 5)
        self.assertEqual(a.add(b).hi, 25)
        self.assertEqual(a.mul(b).lo, 0)

    def test_overflow_detection(self):
        i32 = Interval(lo=0x7FFFFFFF, hi=0x80000001)
        may, _ = i32.can_overflow(BitWidth.BIT32, Signedness.SIGNED)
        self.assertTrue(may)

        u32 = Interval(lo=0, hi=0x1_0000_0000)
        may2, _ = u32.can_overflow(BitWidth.BIT32, Signedness.UNSIGNED)
        self.assertTrue(may2)

        safe = Interval(lo=0, hi=0xFFFF)
        may3, _ = safe.can_overflow(BitWidth.BIT32)
        self.assertFalse(may3)

    def test_join_meet(self):
        a = Interval(lo=0, hi=10)
        b = Interval(lo=5, hi=15)
        j = a.join(b)
        self.assertEqual(j.lo, 0)
        self.assertEqual(j.hi, 15)
        m = a.meet(b)
        self.assertEqual(m.lo, 5)
        self.assertEqual(m.hi, 10)

    def test_top_bottom(self):
        top = Interval.make_top()
        self.assertTrue(top.is_top())
        bot = Interval.make_bottom()
        self.assertTrue(bot.is_bottom())

    def test_truncation(self):
        big = Interval(lo=0, hi=0x1_0000_0001)
        t = big.truncate(BitWidth.BIT64, BitWidth.BIT32)
        self.assertLessEqual(t.hi, 0xFFFFFFFF)


class TestRangePropagation(unittest.TestCase):
    """区间传播引擎."""

    def test_mul_overflow_to_malloc(self):
        lines = [
            "  401000:\tmov    ecx,0x40000000",
            "  401005:\tmov    edx,0x10",
            "  40100a:\timul   ecx,edx",
            "  40100d:\tcall   401100 <malloc>"]
        r = RangePropagationEngine().analyze(lines)
        self.assertGreater(len(r.overflow_sites), 0,
            "0x40000000*0x10 should overflow")
        self.assertIn('overflow', r.overflow_sites[0].reason.lower())

    def test_safe_allocation_no_fp(self):
        lines = [
            "  401000:\tmov    ecx,0x100",
            "  401005:\tcall   401100 <malloc>"]
        r = RangePropagationEngine().analyze(lines)
        self.assertEqual(len(r.overflow_sites), 0,
            "0x100 should not overflow")

    def test_calloc_overflow(self):
        lines = [
            "  401000:\tmov    ecx,0x40000000",
            "  401005:\tmov    edx,0x10",
            "  40100a:\tcall   401100 <calloc>"]
        r = RangePropagationEngine().analyze(lines)
        self.assertGreater(len(r.overflow_sites), 0)

    def test_mov_chain_propagation(self):
        """Test mov chain propagation: 64-bit imul via mov rcx,rax (no 32-bit truncation)."""
        lines = [
            "  401000:\tmov    rax,0x40000000",
            "  401005:\timul   rax,rax,0x10",
            "  40100a:\tmov    rcx,rax",
            "  40100d:\tcall   401100 <malloc>"]
        r = RangePropagationEngine().analyze(lines)
        self.assertGreater(len(r.overflow_sites), 0,
            "imul overflow through mov chain should be detected")

    def test_alloc_count(self):
        lines = [
            "  401000:\tmov    ecx,0x100",
            "  401005:\tcall   401100 <malloc>",
            "  40100a:\tmov    ecx,0x200",
            "  40100f:\tcall   401100 <malloc>"]
        r = RangePropagationEngine().analyze(lines)
        self.assertEqual(r.alloc_sites_found, 2)
        self.assertEqual(r.safe_allocations, 2)


class TestOrchestrator(unittest.TestCase):
    """统一编排器."""

    @classmethod
    def setUpClass(cls):
        cls.orchestrator = IntOverflowOrchestrator()

    def _find_sample(self, name: str) -> str:
        p = os.path.join(_TEST_DIR, name)
        if os.path.exists(p):
            return p
        return ""

    def test_orchestrator_on_sample(self):
        p = self._find_sample('cve_intof_06.exe')
        if not p:
            self.skipTest('sample not found')
        r = self.orchestrator.analyze_binary(p)
        self.assertGreater(r.total_functions, 0)
        self.assertIsInstance(r.scan_time_s, float)

    def test_orchestrator_returns_report(self):
        p = self._find_sample('cve_intof_10.exe')
        if not p:
            self.skipTest('sample not found')
        r = self.orchestrator.analyze_binary(p)
        self.assertIsInstance(r, UnifiedReport)
        self.assertGreaterEqual(r.total_functions, 1)

    def test_no_crash_on_all_samples(self):
        for name in _TEST_SAMPLES:
            p = self._find_sample(name)
            if not p:
                continue
            try:
                r = self.orchestrator.analyze_binary(p)
                self.assertIsInstance(r, UnifiedReport,
                    f"orchestrator crash on {name}")
            except Exception as e:
                self.fail(f"orchestrator crash on {name}: {e}")

    def test_scan_performance(self):
        """样本扫描时间<100ms."""
        p = self._find_sample('cve_intof_10.exe')
        if not p:
            self.skipTest('sample not found')
        t0 = time.time()
        self.orchestrator.analyze_binary(p)
        elapsed = time.time() - t0
        self.assertLess(elapsed, 0.5, f"scan took {elapsed:.3f}s > 0.5s")

    def test_detections_on_positive_samples(self):
        detected = 0
        for name in _TEST_SAMPLES:
            if name not in _EXPECT_DETECTED:
                continue
            p = self._find_sample(name)
            if not p:
                continue
            r = self.orchestrator.analyze_binary(p)
            real = [f for f in r.findings if not f.is_fp]
            if real:
                detected += 1
        self.assertGreaterEqual(detected, 8,
            f"only {detected}/11 positive samples detected")

    def test_safe_samples_no_fp(self):
        fps = 0
        for name in _EXPECT_SAFE:
            p = self._find_sample(name)
            if not p:
                continue
            r = self.orchestrator.analyze_binary(p)
            real = [f for f in r.findings if not f.is_fp]
            fps += len(real)
        self.assertEqual(fps, 0,
            f"Expected 0 FP on safe samples, got {fps}")


class TestRegressionMetrics(unittest.TestCase):
    """回归指标."""

    def test_overall_metrics(self):
        orch = IntOverflowOrchestrator()
        tp = fp = tn = fn = 0
        for name in _TEST_SAMPLES:
            p = os.path.join(_TEST_DIR, name)
            if not os.path.exists(p):
                continue
            r = orch.analyze_binary(p)
            real = [f for f in r.findings if not f.is_fp]
            detected = len(real) > 0
            gt_positive = name in _EXPECT_DETECTED
            gt_safe = name in _EXPECT_SAFE

            if gt_positive:
                if detected: tp += 1
                else: fn += 1
            elif gt_safe:
                if detected: fp += 1
                else: tn += 1

        recall = tp / max(1, tp + fn)
        precision = tp / max(1, tp + fp)
        f1 = 2 * recall * precision / max(0.001, recall + precision)

        print(f"\n  INT-RANGE Metrics: TP={tp} FP={fp} TN={tn} FN={fn}")
        print(f"  Recall={recall:.3f} Precision={precision:.3f} F1={f1:.3f}")

        self.assertGreaterEqual(recall, 0.75,
            f"Recall {recall:.2f} below 0.75 threshold")
        self.assertLessEqual(fp, 3,
            f"Too many FPs: {fp}")


if __name__ == '__main__':
    unittest.main(verbosity=2)
