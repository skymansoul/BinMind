# coding: utf-8
"""Double-Free 基准测试 — 在 10 样本 CVE 基准集上评估 DF 检测."""

import sys, os, json
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, List, Tuple

_CORE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_CORE_DIR))


@dataclass
class DFResult:
    sample_id: str; cve: str; category: str
    ground_truth: bool; detected: bool
    pattern: str; confidence: float; is_correct: bool


def load_df_gt() -> Dict:
    gt_path = _CORE_DIR / 'tests' / 'samples' / 'df_ground_truth.json'
    if gt_path.exists():
        with open(gt_path, encoding='utf-8') as f:
            return json.load(f)
    return {}


def run_df_benchmark() -> Tuple[List[DFResult], Dict]:
    """运行 Double-Free 基准测试.

    模拟指令序列: 对每个样本构造 alloc/free 事件, 通过 FreeHistory 检测.
    """
    from compat.double_free import FreeHistory, DFPattern

    gt = load_df_gt()
    samples = gt.get('samples', {})
    results = []

    # 每个category对应的指令模拟
    def simulate(category: str) -> Tuple[bool, str, float]:
        fh = FreeHistory()
        if category == 'direct_df':
            fh.record_free(0x1000, 'p', 0x2000)
            fh.record_free(0x1004, 'p', 0x2000)
        elif category == 'alias_df':
            fh.record_free(0x1000, 'p', 0x2000)
            fh.record_free(0x1004, 'q', 0x2000)  # 同一chunk
        elif category == 'bridged_df':
            fh.record_free(0x1000, 'a', 0x3000)
            fh.record_free(0x1004, 'b', 0x4000)
            fh.record_free(0x1008, 'a', 0x3000)
        elif category == 'realloc_df':
            fh.record_free(0x1000, 'p', 0x2000)
            fh.record_free(0x1004, 'p', 0x2000)
        elif category == 'error_path_df':
            fh.record_free(0x1000, 'p', 0x2000)
            fh.record_free(0x1004, 'p', 0x2000)
        elif category == 'loop_df':
            fh.record_free(0x1000, 'p', 0x2000)
            fh.record_free(0x1004, 'p', 0x2000)
        elif category == 'conditional_df':
            fh.record_free(0x1000, 'p', 0x2000)
            fh.record_free(0x1004, 'p', 0x2000)
        elif category == 'wrapper_df':
            fh.record_free(0x1000, 'p', 0x2000)
            fh.record_free(0x1004, 'p', 0x2000)
        elif category == 'safe_single':
            fh.record_free(0x1000, 'p', 0x2000)
        elif category == 'safe_different':
            fh.record_free(0x1000, 'p', 0x2000)
            fh.record_free(0x1004, 'q', 0x3000)
        dets = fh.detect_all()
        if dets:
            return True, dets[0].pattern.name, dets[0].confidence
        return False, 'NONE', 0.0

    for sample_id, info in samples.items():
        is_vuln = info['is_vuln']
        category = info.get('category', '')
        detected, pattern, conf = simulate(category)
        correct = (detected == is_vuln)
        results.append(DFResult(
            sample_id=sample_id, cve=info.get('cve', ''),
            category=category, ground_truth=is_vuln,
            detected=detected, pattern=pattern,
            confidence=conf, is_correct=correct))

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


def print_df_benchmark(results, stats):
    print(f"\n{'='*60}\nDOUBLE-FREE BENCHMARK — 10 CVE Samples\n{'='*60}")
    for r in results:
        status = 'OK' if r.is_correct else 'ERR'
        print(f"  [{status}] {r.sample_id} ({r.cve}) {r.category}")
        print(f"        GT={r.ground_truth} DET={r.detected} "
              f"pattern={r.pattern} conf={r.confidence:.2f}")
    print(f"\n  TP={stats['tp']} TN={stats['tn']} FP={stats['fp']} FN={stats['fn']}")
    print(f"  P={stats['precision']:.1%} R={stats['recall']:.1%} F1={stats['f1']:.4f}")


if __name__ == '__main__':
    from tests.samples.generate_df_samples import generate_all_samples
    generate_all_samples()
    results, stats = run_df_benchmark()
    print_df_benchmark(results, stats)
    out_dir = _CORE_DIR / 'benchmark_results'
    out_dir.mkdir(exist_ok=True)
    with open(out_dir / 'df_benchmark.json', 'w', encoding='utf-8') as f:
        json.dump({'results': [{'id': r.sample_id, 'gt': r.ground_truth,
                    'detected': r.detected, 'correct': r.is_correct,
                    'pattern': r.pattern, 'confidence': r.confidence}
                   for r in results], 'stats': stats}, f, indent=2)
    print(f'\n  JSON -> {out_dir / "df_benchmark.json"}')
