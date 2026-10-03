# coding: utf-8
"""Buffer Underflow 基准测试 — 在 10 样本 CVE 基准集上评估 BU 检测."""

import sys, os, json
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, List, Tuple

_CORE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_CORE_DIR))


@dataclass
class BUResult:
    sample_id: str; cve: str; category: str
    ground_truth: bool; detected: bool; risk: str; is_correct: bool


def load_bu_gt() -> Dict:
    gt_path = _CORE_DIR / 'tests' / 'samples' / 'bu_ground_truth.json'
    if gt_path.exists():
        with open(gt_path, encoding='utf-8') as f:
            return json.load(f)
    return {}


def run_bu_benchmark() -> Tuple[List[BUResult], Dict]:
    """运行 Buffer Underflow 基准测试."""
    from compat.buffer_underflow import (
        detect_buffer_underflow, PrevChunkAnalyzer, UnderflowRisk)

    gt = load_bu_gt()
    samples = gt.get('samples', {})
    results = []

    for sample_id, info in samples.items():
        is_vuln = info['is_vuln']
        buf_sz = info.get('buf_sz', 0)
        offset = info.get('offset', 0)
        access_sz = info.get('access_sz', 0)
        prev_chunk_sz = info.get('prev_chunk_sz', 0)
        category = info.get('category', '')

        analysis = detect_buffer_underflow(0, buf_sz, offset, access_sz,
                                           prev_chunk_size=prev_chunk_sz)
        detected = analysis.risk in (UnderflowRisk.LOW, UnderflowRisk.MEDIUM,
                                      UnderflowRisk.HIGH, UnderflowRisk.CRITICAL)

        correct = (detected == is_vuln)
        results.append(BUResult(
            sample_id=sample_id, cve=info.get('cve', ''),
            category=category, ground_truth=is_vuln,
            detected=detected, risk=analysis.risk.name, is_correct=correct))

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


def print_bu_benchmark(results, stats):
    print(f"\n{'='*60}\nBUFFER UNDERFLOW BENCHMARK — 10 CVE Samples\n{'='*60}")
    for r in results:
        status = 'OK' if r.is_correct else 'ERR'
        print(f"  [{status}] {r.sample_id} ({r.cve}) {r.category}")
        print(f"        GT={r.ground_truth} DET={r.detected} risk={r.risk}")
    print(f"\n  TP={stats['tp']} TN={stats['tn']} FP={stats['fp']} FN={stats['fn']}")
    print(f"  P={stats['precision']:.1%} R={stats['recall']:.1%} F1={stats['f1']:.4f}")


if __name__ == '__main__':
    from tests.samples.generate_bu_samples import generate_all_samples
    generate_all_samples()
    results, stats = run_bu_benchmark()
    print_bu_benchmark(results, stats)
    out_dir = _CORE_DIR / 'benchmark_results'
    out_dir.mkdir(exist_ok=True)
    with open(out_dir / 'bu_benchmark.json', 'w', encoding='utf-8') as f:
        json.dump({'results': [{'id': r.sample_id, 'gt': r.ground_truth,
                    'detected': r.detected, 'correct': r.is_correct,
                    'risk': r.risk} for r in results],
                   'stats': stats}, f, indent=2)
    print(f'\n  JSON -> {out_dir / "bu_benchmark.json"}')
