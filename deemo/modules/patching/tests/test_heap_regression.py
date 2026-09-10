# 堆溢出检测集成回归测试 — TP全检出/FP零误报的固化
"""对CVE-2025-TP与FP样本运行HeapOverflowDetector, 固化回归基线。

断言:
  - 所有TP样本(有binary)必须被检出
  - 所有FP样本(有binary)不得被检出
这是WIDV的行为护栏, 防止后续改动引入回归。

用法: python -m pytest tests/test_heap_regression.py -v
"""

import os
import sys
import subprocess
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                '..'))

SAMPLE_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           'cve_samples')

HEAP_TP = [
    'CVE-2025-TP001_tainted_heap_overflow',
    'CVE-2025-TP002_unbounded_heap_overflow',
    'CVE-2025-TP003_loop_bound',
    'CVE-2025-TP004_off_by_one',
    'CVE-2025-TP005_calc_error',
    'CVE-2025-TP006_direct_taint',
    'CVE-2025-TP007_cross_func_alloc',
    'CVE-2025-TP008_mul_size',
    'CVE-2025-TP009_indirect_taint',
    'CVE-2025-TP010_loop_write',
    'CVE-2025-TP011_call_ret_size',
    'CVE-2025-TP012_realloc_expand',
    'CVE-2025-TP013_struct_field',
    'CVE-2025-TP014_array_idx',
    'CVE-2025-TP015_chained_arith',
    'CVE-2025-TP016_strlen_offby',
]
HEAP_FP = [
    'CVE-2025-FP001_constant_malloc_safe',
    'CVE-2025-FP002_guarded_malloc_safe',
    'CVE-2025-FP003_alignment_safe',
    'CVE-2025-FP004_and_mask_guard',
    'CVE-2025-FP005_loop_bound_safe',
    'CVE-2025-FP006_minsize_guard',
    'CVE-2025-FP007_cross_call_valid',
    'CVE-2025-FP008_cmova_capped',
]


def find_binary(d):
    for name in ('vuln_debug.exe', 'vuln_debug'):
        p = os.path.join(SAMPLE_ROOT, d, name)
        if os.path.isfile(p):
            return p
    return None


def detect(sample_dir):
    from src.heap_overflow_detector import HeapOverflowDetector
    from src.asm_normalize import normalize_asm_lines
    binary = find_binary(sample_dir)
    if not binary:
        return None
    r = subprocess.run(['objdump', '-d', '-M', 'intel', binary],
                       capture_output=True, text=True, timeout=30)
    lines = normalize_asm_lines(r.stdout.split('\n'))
    det = HeapOverflowDetector()
    rep = det.detect(lines, sample_dir)
    return rep.true_positives > 0


class TestHeapTPRecall(unittest.TestCase):
    def test_all_tp_detected(self):
        missing = [d for d in HEAP_TP if find_binary(d) is None]
        if missing:
            self.skipTest(f'未编译样本: {missing[:3]}')
        missed = [d for d in HEAP_TP
                  if find_binary(d) and not detect(d)]
        self.assertEqual(missed, [],
                         f'以下TP样本未被检出: {missed}')


class TestHeapFPZeroAlarm(unittest.TestCase):
    def test_no_fp_alarm(self):
        missing = [d for d in HEAP_FP if find_binary(d) is None]
        if missing:
            self.skipTest(f'未编译样本: {missing[:3]}')
        alarmed = [d for d in HEAP_FP
                   if find_binary(d) and detect(d)]
        self.assertEqual(alarmed, [],
                         f'以下安全样本被误报: {alarmed}')


if __name__ == '__main__':
    unittest.main(verbosity=2)
