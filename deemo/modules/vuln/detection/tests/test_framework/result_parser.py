# coding: utf-8
#
"""
结果解析模块——将扫描结果与预期标签比对，计算检出率/误报率/漏报率。
"""

import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class BenchmarkStats:
    """基准测试统计——按漏洞类型分组"""
    total_samples: int = 0
    # 总体
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    # 按类型细分
    by_type: Dict[str, Dict] = field(default_factory=dict)
    # 性能
    avg_elapsed_ms: float = 0.0
    avg_peak_memory_mb: float = 0.0

    @property
    def detection_rate(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def false_positive_rate(self) -> float:
        denom = self.false_positives + self.true_negatives
        return self.false_positives / denom if denom > 0 else 0.0

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def f1_score(self) -> float:
        p, r = self.precision, self.detection_rate
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    def to_dict(self) -> Dict:
        return {
            'total': self.total_samples,
            'tp': self.true_positives, 'fp': self.false_positives,
            'tn': self.true_negatives, 'fn': self.false_negatives,
            'detection_rate': round(self.detection_rate, 3),
            'fpr': round(self.false_positive_rate, 3),
            'precision': round(self.precision, 3),
            'f1': round(self.f1_score, 3),
            'avg_ms': round(self.avg_elapsed_ms, 1),
            'by_type': self.by_type,
        }


def parse_results(scan_results, expected_labels: Dict[str, Dict]
                   ) -> BenchmarkStats:
    """将扫描结果与预期标签比对。

    参数:
      scan_results: [ScanResult] — 扫描器输出
      expected_labels: {cve_id: {vuln_type, expected_vulnerable}}

    返回BenchmarkStats。
    """
    stats = BenchmarkStats()
    stats.total_samples = len(scan_results)
    by_type = {}

    for r in scan_results:
        expected = expected_labels.get(r.cve_id, {})
        exp_type = expected.get('vuln_type', r.vuln_type)
        exp_vuln = expected.get('expected_vulnerable', True)

        # 初始化类型统计
        if exp_type not in by_type:
            by_type[exp_type] = {
                'tp': 0, 'fp': 0, 'tn': 0, 'fn': 0, 'total': 0}
        by_type[exp_type]['total'] += 1

        if exp_vuln and r.detected:
            stats.true_positives += 1
            by_type[exp_type]['tp'] += 1
        elif exp_vuln and not r.detected:
            stats.false_negatives += 1
            by_type[exp_type]['fn'] += 1
        elif not exp_vuln and r.detected:
            stats.false_positives += 1
            by_type[exp_type]['fp'] += 1
        else:
            stats.true_negatives += 1
            by_type[exp_type]['tn'] += 1

        stats.avg_elapsed_ms += r.elapsed_ms

    if stats.total_samples > 0:
        stats.avg_elapsed_ms /= stats.total_samples

    stats.by_type = by_type
    return stats


def print_report(stats: BenchmarkStats):
    """打印人类可读的基准测试报告。"""
    print("=" * 60)
    print("检测基准测试报告")
    print("=" * 60)
    print(f"总样本数:     {stats.total_samples}")
    print(f"检出率:       {stats.detection_rate:.1%}")
    print(f"误报率:       {stats.false_positive_rate:.1%}")
    print(f"精确率:       {stats.precision:.1%}")
    print(f"F1分数:       {stats.f1_score:.3f}")
    print(f"平均耗时:     {stats.avg_elapsed_ms:.0f}ms")
    print(f"TP={stats.true_positives} FP={stats.false_positives} "
          f"FN={stats.false_negatives} TN={stats.true_negatives}")
    print("-" * 60)
    for vtype, counts in sorted(stats.by_type.items()):
        t = counts['total']
        dr = counts['tp'] / max(counts['tp'] + counts['fn'], 1)
        print(f"  {vtype:20s}: {dr:.1%} ({counts['tp']}/{t})")


if __name__ == '__main__':
    # 示例用法
    stats = BenchmarkStats(
        total_samples=10, true_positives=7, false_positives=1,
        false_negatives=2, true_negatives=0)
    print_report(stats)
