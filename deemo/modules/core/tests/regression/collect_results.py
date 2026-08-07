#!/usr/bin/env python3
# coding: utf-8
"""
结果收集与对比模块 — 加载 ground truth, 计算 TP/FP/FN/TN,
输出每个样本的检测状态和汇总指标.
"""

import json, os, sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class SampleVerdict:
    sample_id: str
    expected: bool          # ground truth: 是否应检出
    detected: bool          # 实际是否检出
    candidates: int = 0
    confidence_max: float = 0.0
    wall_time_ms: float = 0.0
    # 分类
    verdict: str = ''       # 'TP' | 'FP' | 'TN' | 'FN'
    detail: str = ''


@dataclass
class RegressionReport:
    samples: List[SampleVerdict]
    total: int = 0
    tp: int = 0; fp: int = 0; tn: int = 0; fn: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    fp_rate: float = 0.0
    avg_time_ms: float = 0.0
    ground_truth_matches: int = 0


def load_ground_truth(path: str) -> Dict[str, bool]:
    """加载 ground truth, 返回 {sample_id: is_vulnerable}."""
    with open(path, 'r', encoding='utf-8') as f:
        raw = json.load(f)
    result = {}
    for sample_id, info in raw.items():
        if isinstance(info, dict):
            result[sample_id] = info.get('heap_overflow', False)
        else:
            result[sample_id] = bool(info)
    return result


def collect(
    scan_results: List[Dict],
    ground_truth_path: str,
    exploitability_threshold: float = 0.3,
) -> RegressionReport:
    """对比扫描结果与 ground truth, 产生报告."""
    gt = load_ground_truth(ground_truth_path)
    verdicts = []

    for sr in scan_results:
        sid = sr.get('sample_id', '')
        candidates = sr.get('candidates', 0)
        detected = sr.get('exploitable', 0) > 0 or candidates > 0

        # 查找 ground truth 匹配
        expected = gt.get(sid)
        if expected is None:
            # 尝试模糊匹配
            for gt_key, gt_val in gt.items():
                if gt_key in sid or sid in gt_key:
                    expected = gt_val
                    break

        if expected is None:
            expected = False  # 保守: 未标注的视为不期望检出

        if expected and detected:
            verdict = 'TP'
        elif not expected and detected:
            verdict = 'FP'
        elif not expected and not detected:
            verdict = 'TN'
        else:
            verdict = 'FN'

        verdicts.append(SampleVerdict(
            sample_id=sid, expected=expected, detected=detected,
            candidates=candidates,
            confidence_max=sr.get('confidence_max', 0.0),
            wall_time_ms=sr.get('wall_time_ms', 0.0),
            verdict=verdict,
            detail=sr.get('error', ''),
        ))

    tp = sum(1 for v in verdicts if v.verdict == 'TP')
    fp = sum(1 for v in verdicts if v.verdict == 'FP')
    tn = sum(1 for v in verdicts if v.verdict == 'TN')
    fn = sum(1 for v in verdicts if v.verdict == 'FN')

    total = len(verdicts)
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = 2 * precision * recall / max(0.001, precision + recall)
    fp_rate = fp / max(1, fp + tn)
    avg_time = sum(v.wall_time_ms for v in verdicts) / max(1, total)
    matches = sum(1 for v in verdicts if v.expected == v.detected)

    return RegressionReport(
        samples=verdicts, total=total,
        tp=tp, fp=fp, tn=tn, fn=fn,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1=round(f1, 4),
        fp_rate=round(fp_rate, 4),
        avg_time_ms=round(avg_time, 1),
        ground_truth_matches=matches,
    )


def report_to_markdown(report: RegressionReport) -> str:
    """将回归报告格式化为 Markdown 表格."""
    lines = [
        '# Regression Test Report',
        '',
        '## Summary',
        '',
        f'| Metric | Value |',
        f'|--------|-------|',
        f'| Total Samples | {report.total} |',
        f'| True Positives (TP) | {report.tp} |',
        f'| False Positives (FP) | {report.fp} |',
        f'| True Negatives (TN) | {report.tn} |',
        f'| False Negatives (FN) | {report.fn} |',
        f'| Precision | {report.precision:.2%} |',
        f'| Recall | {report.recall:.2%} |',
        f'| F1 Score | {report.f1:.3f} |',
        f'| FP Rate | {report.fp_rate:.2%} |',
        f'| Avg Time/Scan | {report.avg_time_ms:.1f}ms |',
        f'| Accuracy (match rate) | {report.ground_truth_matches}/{report.total} |',
        '',
        '## Per-Sample Results',
        '',
        '| Sample ID | Expected | Detected | Verdict | Candidates | Time (ms) |',
        '|-----------|----------|----------|---------|------------|-----------|',
    ]
    for v in report.samples:
        emoji = {'TP': '✓', 'FP': '✗', 'TN': '✓', 'FN': '✗'}
        lines.append(
            f'| {v.sample_id} | {v.expected} | {v.detected} | '
            f'{emoji.get(v.verdict, "?")} {v.verdict} | '
            f'{v.candidates} | {v.wall_time_ms:.0f} |')
    return '\n'.join(lines)


def report_to_csv(report: RegressionReport) -> str:
    """输出 CSV 格式."""
    lines = ['sample_id,expected,detected,verdict,candidates,time_ms']
    for v in report.samples:
        lines.append(
            f'{v.sample_id},{v.expected},{v.detected},'
            f'{v.verdict},{v.candidates},{v.wall_time_ms:.0f}')
    return '\n'.join(lines)


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('scan_results_json', help='run_scanner.py 输出的 JSON')
    ap.add_argument('--ground-truth', required=True, help='ground_truth.json 路径')
    ap.add_argument('--threshold', type=float, default=0.3)
    ap.add_argument('--format', default='markdown',
                    choices=['markdown', 'csv', 'json'])
    ap.add_argument('--output', help='输出文件路径')
    args = ap.parse_args()

    with open(args.scan_results_json, 'r') as f:
        scan_data = json.load(f)

    results = scan_data.get('results', scan_data)
    report = collect(results, args.ground_truth, args.threshold)

    if args.format == 'markdown':
        output = report_to_markdown(report)
    elif args.format == 'csv':
        output = report_to_csv(report)
    else:
        output = json.dumps({
            'summary': {
                'tp': report.tp, 'fp': report.fp,
                'tn': report.tn, 'fn': report.fn,
                'precision': report.precision,
                'recall': report.recall,
                'f1': report.f1,
                'fp_rate': report.fp_rate,
            },
            'samples': [
                {'id': v.sample_id, 'verdict': v.verdict,
                 'expected': v.expected, 'detected': v.detected}
                for v in report.samples
            ],
        }, indent=2)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
    else:
        print(output)
