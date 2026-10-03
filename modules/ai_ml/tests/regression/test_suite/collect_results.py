# 结果收集与对比模块——汇总扫描结果并生成对比报告
# 输出:
#   1. 终端摘要(检出率/误报率/漏报率对比)
#   2. JSON格式详细结果
#   3. CSV格式对比表(可直接导入Excel/LaTeX)

import json
import sys
import csv
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Tuple

SUITE_DIR = Path(__file__).parent
SCAN_RESULTS = SUITE_DIR / "scan_results.json"
COMPILE_RESULTS = SUITE_DIR / "compile_results.json"
SUMMARY_JSON = SUITE_DIR / "summary.json"
SUMMARY_CSV = SUITE_DIR / "comparison_table.csv"


@dataclass
class ComparisonSummary:
    method: str
    total_samples: int
    true_positive_samples: int
    true_negative_samples: int
    detected_positives: int       # TP
    detected_negatives: int       # FP
    missed_positives: int         # FN
    correct_negatives: int        # TN
    recall: float                 # TP / (TP + FN)
    precision: float              # TP / (TP + FP)
    false_positive_rate: float    # FP / (FP + TN)
    avg_time_ms: float
    confirmed_count: int
    likely_count: int
    filtered_count: int


def load_scan_results() -> List[Dict]:
    if SCAN_RESULTS.exists():
        with open(SCAN_RESULTS) as f:
            return json.load(f)
    return []


def compute_metrics(results: List[Dict], prefix: str) -> ComparisonSummary:
    """计算指定方法(original/enhanced)的检测指标"""
    tp_samples = 0
    tn_samples = 0
    tp = 0  # detected positives
    fp = 0  # detected negatives
    fn = 0  # missed positives
    tn = 0  # correct negatives
    total_time = 0.0
    confirmed = 0
    likely = 0
    filtered = 0

    for r in results:
        is_vuln = r.get('is_true_positive', True)
        if is_vuln:
            tp_samples += 1
        else:
            tn_samples += 1

        detected = r.get(f'{prefix}_detected', False)
        total_time += r.get(f'{prefix}_time_ms', 0)
        confirmed += r.get(f'{prefix}_confirmed', 0)
        likely += r.get(f'{prefix}_likely', 0)
        filtered += r.get(f'{prefix}_filtered', 0)

        if is_vuln and detected:
            tp += 1
        elif is_vuln and not detected:
            fn += 1
        elif not is_vuln and detected:
            fp += 1
        elif not is_vuln and not detected:
            tn += 1

    total = tp + fp + fn + tn
    recall = tp / max(1, tp + fn)
    precision = tp / max(1, tp + fp)
    fpr = fp / max(1, fp + tn)

    return ComparisonSummary(
        method=prefix,
        total_samples=total,
        true_positive_samples=tp_samples,
        true_negative_samples=tn_samples,
        detected_positives=tp,
        detected_negatives=fp,
        missed_positives=fn,
        correct_negatives=tn,
        recall=recall,
        precision=precision,
        false_positive_rate=fpr,
        avg_time_ms=total_time / max(1, total),
        confirmed_count=confirmed,
        likely_count=likely,
        filtered_count=filtered,
    )


def generate_comparison(scan_results: List[Dict]) -> Tuple[ComparisonSummary, ComparisonSummary]:
    """生成原始vs增强的完整对比"""
    orig = compute_metrics(scan_results, 'original')
    enh = compute_metrics(scan_results, 'enhanced')
    return orig, enh


def print_summary(orig: ComparisonSummary, enh: ComparisonSummary):
    """终端友好的对比摘要"""
    print("\n" + "=" * 70)
    print("HEAP OVERFLOW DETECTION — ORIGINAL vs ENHANCED")
    print("=" * 70)
    print(f"{'Metric':<30} {'Original':>18} {'Enhanced':>18}")
    print("-" * 70)
    print(f"{'Total Samples':<30} {orig.total_samples:>18} {enh.total_samples:>18}")
    print(f"{'True Positives (vuln)':<30} {orig.true_positive_samples:>18} {enh.true_positive_samples:>18}")
    print(f"{'True Negatives (safe)':<30} {orig.true_negative_samples:>18} {enh.true_negative_samples:>18}")
    print("-" * 70)
    print(f"{'Recall (检出率)':<30} {orig.recall:>17.1%} {enh.recall:>17.1%}")
    print(f"{'Precision (精确率)':<30} {orig.precision:>17.1%} {enh.precision:>17.1%}")
    print(f"{'FPR (误报率)':<30} {orig.false_positive_rate:>17.1%} {enh.false_positive_rate:>17.1%}")
    print("-" * 70)
    print(f"{'Avg Time (ms)':<30} {orig.avg_time_ms:>17.1f} {enh.avg_time_ms:>17.1f}")
    print(f"{'CONFIRMED alerts':<30} {orig.confirmed_count:>18} {enh.confirmed_count:>18}")
    print(f"{'LIKELY alerts':<30} {orig.likely_count:>18} {enh.likely_count:>18}")
    print(f"{'FILTERED (误报排除)':<30} {orig.filtered_count:>18} {enh.filtered_count:>18}")
    print("=" * 70)

    # 计算改进幅度
    if orig.false_positive_rate > 0:
        fpr_reduction = (orig.false_positive_rate - enh.false_positive_rate) / orig.false_positive_rate * 100
        print(f"\n误报率降低: {fpr_reduction:+.1f}%")
    if orig.recall > 0:
        recall_change = (enh.recall - orig.recall) / orig.recall * 100
        print(f"召回率变化: {recall_change:+.1f}%")


def export_json(orig: ComparisonSummary, enh: ComparisonSummary):
    with open(SUMMARY_JSON, 'w') as f:
        json.dump({
            'original': asdict(orig),
            'enhanced': asdict(enh),
        }, f, indent=2)
    print(f"\nJSON summary: {SUMMARY_JSON}")


def export_csv(orig: ComparisonSummary, enh: ComparisonSummary):
    rows = [
        ['Method', 'Samples', 'Recall', 'Precision', 'FPR',
         'AvgTime_ms', 'TP', 'FP', 'FN', 'TN', 'Confirmed', 'Likely', 'Filtered'],
        ['Original', orig.total_samples, f'{orig.recall:.3f}',
         f'{orig.precision:.3f}', f'{orig.false_positive_rate:.3f}',
         f'{orig.avg_time_ms:.1f}', orig.detected_positives,
         orig.detected_negatives, orig.missed_positives,
         orig.correct_negatives, orig.confirmed_count,
         orig.likely_count, orig.filtered_count],
        ['Enhanced', enh.total_samples, f'{enh.recall:.3f}',
         f'{enh.precision:.3f}', f'{enh.false_positive_rate:.3f}',
         f'{enh.avg_time_ms:.1f}', enh.detected_positives,
         enh.detected_negatives, enh.missed_positives,
         enh.correct_negatives, enh.confirmed_count,
         enh.likely_count, enh.filtered_count],
    ]
    with open(SUMMARY_CSV, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerows(rows)
    print(f"CSV table: {SUMMARY_CSV}")


def main():
    scan_results = load_scan_results()
    if not scan_results:
        print("No scan results found. Run run_scanner.py first.")
        return 1

    orig, enh = generate_comparison(scan_results)
    print_summary(orig, enh)
    export_json(orig, enh)
    export_csv(orig, enh)
    return 0


if __name__ == '__main__':
    sys.exit(main())
