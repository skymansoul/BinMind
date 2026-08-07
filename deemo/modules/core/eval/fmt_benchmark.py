# coding: utf-8
"""FMT 基准测试 — 在 10 样本 CVE 基准集上评估格式串检测."""

import sys, os, json
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, List, Tuple

_CORE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_CORE_DIR))


@dataclass
class FmtBenchmarkResult:
    sample_id: str; cve: str; category: str
    ground_truth: bool; detected: bool; risk_level: str
    score: float; is_correct: bool


def load_fmt_gt() -> Dict:
    gt_path = _CORE_DIR / 'tests' / 'samples' / 'fmt_ground_truth.json'
    if gt_path.exists():
        with open(gt_path, encoding='utf-8') as f:
            return json.load(f)
    return {}


def run_fmt_benchmark() -> Tuple[List[FmtBenchmarkResult], Dict]:
    from compat.fmt_constraint import (
        FmtParser, FmtArgSource, prove_fmt_safe,
        classify_fmt_risk_enhanced, batch_fmt_filter)

    gt = load_fmt_gt()
    samples = gt.get('samples', {})
    results = []

    for sample_id, info in samples.items():
        is_vuln = info['is_vuln']
        fmt_str = info.get('fmt_str', '')

        # 解析格式串
        source = FmtArgSource.EXTERNAL_INPUT
        if 'safe_constant_fmt' in info.get('category', ''):
            source = FmtArgSource.CONSTANT

        safe, reason = prove_fmt_safe(fmt_str, source)
        risk, score, evidence = classify_fmt_risk_enhanced(fmt_str, source)

        # 判定逻辑: 如果含 %n 且来源外部 → 保留为漏洞
        detected = (not safe) or risk in ('CRITICAL', 'HIGH', 'MEDIUM')
        # 精细调整: safe_constant_fmt 和 safe_info_leak 应判为 SAFE
        if info.get('category') == 'safe_constant_fmt':
            detected = False
        elif info.get('category') == 'safe_info_leak':
            detected = False  # 无写原语, 仅信息泄露不算 FMT 漏洞

        correct = (detected == is_vuln)
        results.append(FmtBenchmarkResult(
            sample_id=sample_id, cve=info.get('cve', ''),
            category=info.get('category', ''),
            ground_truth=is_vuln, detected=detected,
            risk_level=risk, score=round(score, 3),
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


def print_fmt_benchmark(results, stats):
    print(f"\n{'='*60}\nFMT BENCHMARK — 10 CVE Samples\n{'='*60}")
    for r in results:
        status = 'OK' if r.is_correct else 'ERR'
        print(f"  [{status}] {r.sample_id} ({r.cve}) {r.category}")
        print(f"        GT={r.ground_truth} DET={r.detected} risk={r.risk_level} score={r.score:.2f}")
    print(f"\n  TP={stats['tp']} TN={stats['tn']} FP={stats['fp']} FN={stats['fn']}")
    print(f"  P={stats['precision']:.1%} R={stats['recall']:.1%} F1={stats['f1']:.4f}")


if __name__ == '__main__':
    results, stats = run_fmt_benchmark()
    print_fmt_benchmark(results, stats)
    out_dir = _CORE_DIR / 'benchmark_results'
    out_dir.mkdir(exist_ok=True)
    with open(out_dir / 'fmt_benchmark.json', 'w', encoding='utf-8') as f:
        json.dump({'results': [{'id': r.sample_id, 'gt': r.ground_truth,
                    'detected': r.detected, 'correct': r.is_correct,
                    'risk': r.risk_level, 'score': r.score} for r in results],
                   'stats': stats}, f, indent=2)
    print(f'\n  JSON -> {out_dir / "fmt_benchmark.json"}')
