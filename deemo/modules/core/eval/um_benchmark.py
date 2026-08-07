# coding: utf-8
"""Uninitialized Memory 基准测试 — 在 10 样本 CVE 基准集上评估 UM 检测."""

import sys, os, json
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, List, Tuple

_CORE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_CORE_DIR))


@dataclass
class UMResult:
    sample_id: str; cve: str; category: str
    ground_truth: bool; detected: bool; is_correct: bool


def load_um_gt() -> Dict:
    gt_path = _CORE_DIR / 'tests' / 'samples' / 'um_ground_truth.json'
    if gt_path.exists():
        with open(gt_path, encoding='utf-8') as f:
            return json.load(f)
    return {}


def run_um_benchmark() -> Tuple[List[UMResult], Dict]:
    """运行 Uninitialized Memory 基准测试."""
    from compat.uninitialized_memory import InitTracker

    gt = load_um_gt()
    samples = gt.get('samples', {})
    results = []

    for sample_id, info in samples.items():
        is_vuln = info['is_vuln']
        alloc_sz = info.get('alloc_sz', 0)
        write_start = info.get('write_start', 0)
        write_end = info.get('write_end', 0)
        read_start = info.get('read_start', 0)
        read_end = info.get('read_end', 0)
        category = info.get('category', '')

        it = InitTracker()
        obj_addr = 0x1000
        it.record_alloc(0x4000, alloc_sz, 'ptr')

        # 部分写入
        if write_end > write_start:
            it.record_write(0x4000, write_start, write_end - write_start)

        # 检查读取
        r = it.check_use(0x4000, read_start, read_end - read_start, 0x5000)
        detected = r is not None and r.is_dangerous

        correct = (detected == is_vuln)
        results.append(UMResult(
            sample_id=sample_id, cve=info.get('cve', ''),
            category=category, ground_truth=is_vuln,
            detected=detected, is_correct=correct))

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


def print_um_benchmark(results, stats):
    print(f"\n{'='*60}\nUNINITIALIZED MEMORY BENCHMARK — 10 CVE Samples\n{'='*60}")
    for r in results:
        status = 'OK' if r.is_correct else 'ERR'
        print(f"  [{status}] {r.sample_id} ({r.cve}) {r.category}")
        print(f"        GT={r.ground_truth} DET={r.detected}")
    print(f"\n  TP={stats['tp']} TN={stats['tn']} FP={stats['fp']} FN={stats['fn']}")
    print(f"  P={stats['precision']:.1%} R={stats['recall']:.1%} F1={stats['f1']:.4f}")


if __name__ == '__main__':
    from tests.samples.generate_um_samples import generate_all_samples
    generate_all_samples()
    results, stats = run_um_benchmark()
    print_um_benchmark(results, stats)
    out_dir = _CORE_DIR / 'benchmark_results'
    out_dir.mkdir(exist_ok=True)
    with open(out_dir / 'um_benchmark.json', 'w', encoding='utf-8') as f:
        json.dump({'results': [{'id': r.sample_id, 'gt': r.ground_truth,
                    'detected': r.detected, 'correct': r.is_correct}
                   for r in results], 'stats': stats}, f, indent=2)
    print(f'\n  JSON -> {out_dir / "um_benchmark.json"}')
