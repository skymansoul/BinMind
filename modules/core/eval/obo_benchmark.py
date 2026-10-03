# coding: utf-8
"""Off-by-One 基准测试 — 在 10 样本 CVE 基准集上评估 OBO 检测."""

import sys, os, json
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, List, Tuple

_CORE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_CORE_DIR))


@dataclass
class OBOResult:
    sample_id: str; cve: str; category: str
    ground_truth: bool; detected: bool
    risk: str; is_off_by_one: bool; is_correct: bool


def load_obo_gt() -> Dict:
    gt_path = _CORE_DIR / 'tests' / 'samples' / 'obo_ground_truth.json'
    if gt_path.exists():
        with open(gt_path, encoding='utf-8') as f:
            return json.load(f)
    return {}


def run_obo_benchmark() -> Tuple[List[OBOResult], Dict]:
    """运行 Off-by-One 基准测试.

    metadata=8: glibc中PREV_INUSE置位时prev_size可复用, 有效开销仅8字节.
    """
    from compat.off_by_one import detect_off_by_one, ChunkLayout, OBORisk

    gt = load_obo_gt()
    samples = gt.get('samples', {})
    results = []

    for sample_id, info in samples.items():
        is_vuln = info['is_vuln']
        alloc = info.get('alloc', 0)
        write = info.get('write', 0)
        adj_alloc = info.get('adj_alloc', 0) or None
        category = info.get('category', '')

        analysis = detect_off_by_one(alloc, write, adjacent_alloc=adj_alloc, metadata=8)
        detected = False
        if analysis.is_off_by_one:
            detected = True  # off-by-one 检测到
        elif analysis.risk in (OBORisk.CRITICAL, OBORisk.HIGH):
            detected = True  # 常规溢出也是漏洞
        elif write > 0:
            usable = ChunkLayout.compute_usable(alloc, metadata=8)
            if write > usable:
                detected = True

        correct = (detected == is_vuln)
        results.append(OBOResult(
            sample_id=sample_id, cve=info.get('cve', ''),
            category=category, ground_truth=is_vuln,
            detected=detected, risk=analysis.risk.name,
            is_off_by_one=analysis.is_off_by_one, is_correct=correct))

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


def print_obo_benchmark(results, stats):
    print(f"\n{'='*60}\nOFF-BY-ONE BENCHMARK — 10 CVE Samples\n{'='*60}")
    for r in results:
        status = 'OK' if r.is_correct else 'ERR'
        print(f"  [{status}] {r.sample_id} ({r.cve}) {r.category}")
        print(f"        GT={r.ground_truth} DET={r.detected} "
              f"OBO={r.is_off_by_one} risk={r.risk}")
    print(f"\n  TP={stats['tp']} TN={stats['tn']} FP={stats['fp']} FN={stats['fn']}")
    print(f"  P={stats['precision']:.1%} R={stats['recall']:.1%} F1={stats['f1']:.4f}")


if __name__ == '__main__':
    from tests.samples.generate_obo_samples import generate_all_samples
    generate_all_samples()
    results, stats = run_obo_benchmark()
    print_obo_benchmark(results, stats)
    out_dir = _CORE_DIR / 'benchmark_results'
    out_dir.mkdir(exist_ok=True)
    with open(out_dir / 'obo_benchmark.json', 'w', encoding='utf-8') as f:
        json.dump({'results': [{'id': r.sample_id, 'gt': r.ground_truth,
                    'detected': r.detected, 'correct': r.is_correct,
                    'risk': r.risk, 'obo': r.is_off_by_one} for r in results],
                   'stats': stats}, f, indent=2)
    print(f'\n  JSON -> {out_dir / "obo_benchmark.json"}')
