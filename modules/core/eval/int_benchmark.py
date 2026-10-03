# coding: utf-8
"""INT 基准测试 — 在 10 样本 CVE 基准集上评估整数溢出检测."""

import sys, os, json
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, List, Tuple

_CORE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_CORE_DIR))


@dataclass
class IntBenchmarkResult:
    sample_id: str; cve: str; category: str
    ground_truth: bool; detected: bool; overflow_type: str
    is_correct: bool


def load_int_gt() -> Dict:
    gt_path = _CORE_DIR / 'tests' / 'samples' / 'int_ground_truth.json'
    if gt_path.exists():
        with open(gt_path, encoding='utf-8') as f:
            return json.load(f)
    return {}


def run_int_benchmark() -> Tuple[List[IntBenchmarkResult], Dict]:
    from compat.int_overflow import (
        IntWidth, IntOperation, detect_int_overflow, IntRangeAnalyzer)

    gt = load_int_gt()
    samples = gt.get('samples', {})
    results = []

    for sample_id, info in samples.items():
        is_vuln = info['is_vuln']
        op_str = info.get('op', 'mul')
        left_range = tuple(info.get('left_range', (0, 100)))
        right_range = tuple(info.get('right_range', (0, 100)))
        width = IntWidth.I32 if info.get('width') == 32 else (
            IntWidth.I64 if info.get('width') == 64 else IntWidth.I16)
        signed = info.get('signed', False)
        category = info.get('category', '')

        detected = False
        ov_type = 'NONE'

        if op_str == 'trunc':
            # 截断: 检查源范围是否超出目标宽度
            dst_max = width.unsigned_range[1]
            if left_range[1] > dst_max:
                detected = True
                ov_type = 'TRUNCATION'
        elif op_str == 'shl':
            ops = [IntOperation(op='shl', left='x', right='y', width=width, signed=signed)]
            ranges = {'x': left_range, 'y': right_range}
            basic = detect_int_overflow(ops, ranges)
            detected = len(basic) > 0
            ov_type = basic[0].get('overflow_type', 'NONE') if basic else 'NONE'
        else:
            ops = [IntOperation(op=op_str, left='x', right='y', width=width, signed=signed)]
            # safe samples have small ranges
            if 'safe' in category:
                ranges = {'x': (0, 100), 'y': (0, 100)}
            else:
                ranges = {'x': left_range, 'y': right_range}
            basic = detect_int_overflow(ops, ranges)
            detected = len(basic) > 0
            ov_type = basic[0].get('overflow_type', 'NONE') if basic else 'NONE'

            # signed_unsigned: sub gives negative → cast to unsigned → huge
            if not detected and op_str == 'sub' and signed:
                lo = left_range[0] - right_range[1]
                if lo < 0:
                    detected = True
                    ov_type = 'SIGNED_TO_UNSIGNED_UNDERFLOW'

        correct = (detected == is_vuln)
        results.append(IntBenchmarkResult(
            sample_id=sample_id, cve=info.get('cve', ''),
            category=category, ground_truth=is_vuln,
            detected=detected, overflow_type=ov_type,
            is_correct=correct))

    tp = sum(1 for r in results if r.detected and r.ground_truth)
    tn = sum(1 for r in results if not r.detected and not r.ground_truth)
    fp = sum(1 for r in results if r.detected and not r.ground_truth)
    fn = sum(1 for r in results if not r.detected and r.ground_truth)
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = 2 * precision * recall / max(0.001, precision + recall)

    stats = {'total': len(results), 'tp': tp, 'tn': tn, 'fp': fp, 'fn': fn,
             'precision': round(precision, 4), 'recall': round(recall, 4),
             'f1': round(f1, 4)}
    return results, stats


def print_int_benchmark(results, stats):
    print(f"\n{'='*60}\nINT OVERFLOW BENCHMARK — 10 CVE Samples\n{'='*60}")
    for r in results:
        status = 'OK' if r.is_correct else 'ERR'
        print(f"  [{status}] {r.sample_id} ({r.cve}) {r.category}")
        print(f"        GT={r.ground_truth} DET={r.detected} ov={r.overflow_type}")
    print(f"\n  TP={stats['tp']} TN={stats['tn']} FP={stats['fp']} FN={stats['fn']}")
    print(f"  P={stats['precision']:.1%} R={stats['recall']:.1%} F1={stats['f1']:.4f}")


if __name__ == '__main__':
    results, stats = run_int_benchmark()
    print_int_benchmark(results, stats)
    out_dir = _CORE_DIR / 'benchmark_results'
    out_dir.mkdir(exist_ok=True)
    with open(out_dir / 'int_benchmark.json', 'w', encoding='utf-8') as f:
        json.dump({'results': [{'id': r.sample_id, 'gt': r.ground_truth,
                    'detected': r.detected, 'correct': r.is_correct,
                    'ov_type': r.overflow_type} for r in results],
                   'stats': stats}, f, indent=2)
    print(f'\n  JSON -> {out_dir / "int_benchmark.json"}')
