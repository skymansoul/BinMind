"""结果收集与对比模块 — 合并扫描结果, 计算统计指标, 生成报告.

用法: python collect_results.py <results_dir> [--output report.json]
  生成: results_summary.json, report.md
"""

import os
import sys
import json
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple
from collections import defaultdict


@dataclass
class SampleVerdict:
    """单个样本的最终判定."""
    sample_id: str
    cve_id: str
    vuln_type: str = "heap_overflow"
    # 检测状态
    detected: bool = False           # 是否检出 (不含被过滤的FP)
    n_findings_total: int = 0       # 总发现数
    n_findings_confirmed: int = 0   # 确认发现数 (非 FP)
    n_fp_filtered: int = 0          # 被过滤的 FP
    # 裁定
    verdict: str = "pending"        # tp / fp / fn / tn
    # 性能
    time_s: float = 0.0
    # 备注
    note: str = ""


@dataclass
class RegressionReport:
    """回归测试总报告."""
    timestamp: str = ""
    total_samples: int = 0
    # 混淆矩阵
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    true_negatives: int = 0
    # 指标
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    fp_rate: float = 0.0           # FP / (FP + TN)
    # 性能
    total_time_s: float = 0.0
    avg_time_s: float = 0.0
    # 详情
    per_sample: List[SampleVerdict] = field(default_factory=list)
    # 对比: plain vs packed
    plain_summary: dict = field(default_factory=dict)
    packed_summary: dict = field(default_factory=dict)


class ResultCollector:
    """结果收集器 — 聚合扫描输出, 计算统计."""

    def __init__(self, results_dir: str):
        self._results_dir = os.path.abspath(results_dir)
        self._raw_results: List[dict] = []
        self._verdicts: List[SampleVerdict] = []
        self._report = RegressionReport()

    def load(self) -> List[dict]:
        """加载原始扫描结果 JSON."""
        path = os.path.join(self._results_dir, 'scan_results.json')
        if os.path.isfile(path):
            with open(path) as f:
                self._raw_results = json.load(f)
        return self._raw_results

    def load_ground_truth(self, gt_path: str = '') -> dict:
        """加载 ground truth 标注.

        GT 格式: {sample_id: {'has_vuln': bool, 'vuln_type': str, ...}}
        若未提供, 使用自标注: 样本 ID 包含 'vuln'/'cve' → has_vuln=True
        """
        if gt_path and os.path.isfile(gt_path):
            with open(gt_path) as f:
                return json.load(f)
        return {}

    def compute(self, ground_truth: Optional[dict] = None) -> RegressionReport:
        """计算所有指标."""
        if not self._raw_results:
            self.load()

        gt = ground_truth or {}
        self._verdicts = []
        report = self._report

        total_findings = 0
        total_fp_filtered = 0

        plain_tp = plain_fp = plain_fn = plain_tn = 0
        packed_tp = packed_fp = packed_fn = packed_tn = 0

        for r in self._raw_results:
            sid = r.get('sample_id', '')
            is_packed = r.get('is_packed', False)
            findings = r.get('findings', [])
            n_total = r.get('n_findings', 0)
            n_fp = r.get('n_filtered_fp', 0)
            n_confirmed = n_total - n_fp
            detected = n_confirmed > 0

            # GT 判定
            gt_info = gt.get(sid, {})
            has_vuln = gt_info.get('has_vuln', self._guess_has_vuln(sid))

            if has_vuln:
                if detected:
                    verdict = 'tp'
                else:
                    verdict = 'fn'
            else:
                if detected:
                    verdict = 'fp'
                else:
                    verdict = 'tn'

            v = SampleVerdict(
                sample_id=sid,
                cve_id=r.get('cve_id', ''),
                vuln_type=r.get('vuln_type', 'heap_overflow'),
                detected=detected,
                n_findings_total=n_total,
                n_findings_confirmed=n_confirmed,
                n_fp_filtered=n_fp,
                verdict=verdict,
                time_s=r.get('time_elapsed_s', 0.0),
            )
            self._verdicts.append(v)

            # 更新计数器
            if verdict == 'tp':
                if is_packed: packed_tp += 1
                else: plain_tp += 1
            elif verdict == 'fp':
                if is_packed: packed_fp += 1
                else: plain_fp += 1
            elif verdict == 'fn':
                if is_packed: packed_fn += 1
                else: plain_fn += 1
            elif verdict == 'tn':
                if is_packed: packed_tn += 1
                else: plain_tn += 1

            total_findings += n_total
            total_fp_filtered += n_fp

        # 填充报告
        report.total_samples = len(self._raw_results)
        report.true_positives = plain_tp + packed_tp
        report.false_positives = plain_fp + packed_fp
        report.false_negatives = plain_fn + packed_fn
        report.true_negatives = plain_tn + packed_tn

        # 指标
        denom_p = report.true_positives + report.false_positives
        denom_r = report.true_positives + report.false_negatives
        report.precision = report.true_positives / max(1, denom_p)
        report.recall = report.true_positives / max(1, denom_r)
        report.f1_score = (
            2 * report.precision * report.recall / max(0.001, report.precision + report.recall))
        report.fp_rate = report.false_positives / max(1, report.false_positives + report.true_negatives)

        # 性能
        times = [v.time_s for v in self._verdicts if v.time_s > 0]
        report.total_time_s = sum(times)
        report.avg_time_s = report.total_time_s / max(1, len(times))

        # 分组
        report.plain_summary = {
            'tp': plain_tp, 'fp': plain_fp, 'fn': plain_fn, 'tn': plain_tn,
            'count': plain_tp + plain_fp + plain_fn + plain_tn,
        }
        report.packed_summary = {
            'tp': packed_tp, 'fp': packed_fp, 'fn': packed_fn, 'tn': packed_tn,
            'count': packed_tp + packed_fp + packed_fn + packed_tn,
        }

        report.per_sample = self._verdicts

        # 时间戳
        from datetime import datetime
        report.timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        self._report = report
        return report

    @staticmethod
    def _guess_has_vuln(sample_id: str) -> bool:
        """从样本ID猜测是否包含漏洞 (无GT时的自标注)."""
        sid_lower = sample_id.lower()
        # 漏洞样本标识
        if any(x in sid_lower for x in ('cve', 'vuln', 'overflow', 'heap', 'uaf')):
            return True
        # 安全样本标识
        if any(x in sid_lower for x in ('safe', 'clean', 'normal', 'benign')):
            return False
        return True  # 默认假设有漏洞 (我们的样本集全为漏洞样本)

    def write_report(self, output_path: str = '') -> str:
        """生成 Markdown 和 JSON 报告."""
        if not self._report.total_samples:
            self.compute()

        rdir = self._results_dir

        # JSON
        json_path = os.path.join(rdir, 'regression_report.json')
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(asdict(self._report), f, indent=2, ensure_ascii=False,
                     default=str)

        # Markdown
        md_path = os.path.join(rdir, 'regression_report.md')
        report = self._report
        lines = [
            f"# Regression Test Report",
            f"**Generated:** {report.timestamp}",
            f"",
            f"## Summary",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Total Samples | {report.total_samples} |",
            f"| True Positives | {report.true_positives} |",
            f"| False Positives | {report.false_positives} |",
            f"| False Negatives | {report.false_negatives} |",
            f"| True Negatives | {report.true_negatives} |",
            f"| **Precision** | **{report.precision:.3f}** |",
            f"| **Recall** | **{report.recall:.3f}** |",
            f"| **F1 Score** | **{report.f1_score:.3f}** |",
            f"| FP Rate | {report.fp_rate:.3f} |",
            f"| Avg Time | {report.avg_time_s:.2f}s |",
            f"",
            f"## Per-Sample Results",
            f"| Sample | CVE | Verdict | Findings | FP Filtered | Time (s) |",
            f"|--------|-----|---------|----------|-------------|----------|",
        ]
        for v in report.per_sample:
            emoji = {'tp': '✅', 'fp': '⚠️', 'fn': '❌', 'tn': '✓', 'pending': '❓'}
            lines.append(
                f"| {v.sample_id} | {v.cve_id} | {emoji.get(v.verdict, '?')} {v.verdict} "
                f"| {v.n_findings_total} | {v.n_fp_filtered} | {v.time_s:.2f} |")

        lines.extend([
            "",
            "## Plain vs Packed",
            f"| Group | TP | FP | FN | TN | Count |",
            f"|-------|----|----|----|----|-------|",
            f"| Plain | {report.plain_summary['tp']} | {report.plain_summary['fp']} | "
            f"{report.plain_summary['fn']} | {report.plain_summary['tn']} | "
            f"{report.plain_summary['count']} |",
            f"| Packed | {report.packed_summary['tp']} | {report.packed_summary['fp']} | "
            f"{report.packed_summary['fn']} | {report.packed_summary['tn']} | "
            f"{report.packed_summary['count']} |",
        ])

        with open(md_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines) + '\n')

        return md_path

    def summary(self) -> str:
        """控制台摘要."""
        if not self._report.total_samples:
            self.compute()
        r = self._report
        return (
            f"=== Regression Summary ===\n"
            f"  Samples:  {r.total_samples}\n"
            f"  TP: {r.true_positives}  FP: {r.false_positives}  "
            f"FN: {r.false_negatives}  TN: {r.true_negatives}\n"
            f"  Precision: {r.precision:.3f}  Recall: {r.recall:.3f}  "
            f"F1: {r.f1_score:.3f}\n"
            f"  FP Rate:   {r.fp_rate:.3f}  "
            f"Avg Time: {r.avg_time_s:.2f}s\n"
        )


# CLI
if __name__ == '__main__':
    results_dir = sys.argv[1] if len(sys.argv) > 1 else '../results'
    collector = ResultCollector(results_dir)
    collector.load()
    collector.compute()
    print(collector.summary())
    collector.write_report()
