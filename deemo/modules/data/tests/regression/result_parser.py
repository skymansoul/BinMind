# 结果解析与统计 — 从扫描结果计算检出率/误报率/漏报率.
# 创建: 2026-08-05

import json, os
from collections import defaultdict
from typing import Dict, List, Optional

class ResultParser:
    """解析扫描结果, 输出性能统计."""

    def __init__(self, ground_truth: Dict[str, dict] = None):
        # ground_truth: {sample_name: {cve_id, vuln_type, vuln_count}}
        self._gt = ground_truth or {}

    def parse(self, scan_results: List[dict]) -> dict:
        """解析扫描结果列表 → 统计摘要."""
        stats = {
            "total_samples": len(scan_results),
            "total_findings": 0,
            "true_positives": 0,
            "false_positives": 0,
            "false_negatives": 0,
            "by_type": defaultdict(lambda: {"tp":0,"fp":0,"fn":0}),
            "by_severity": defaultdict(int),
            "per_sample": [],
        }

        for r in scan_results:
            sample = r.get("sample_name", "unknown")
            gt = self._gt.get(sample, {})
            gt_type = gt.get("vuln_type", "unknown")
            gt_count = gt.get("vuln_count", 1)

            findings = r.get("findings", [])
            stats["total_findings"] += len(findings)

            # 简化分类: 有finding且类型匹配 → TP, 有finding但类型不匹配 → FP
            matched = sum(1 for f in findings
                         if f.get("type","") in str(gt_type))
            unmatched = len(findings) - matched

            if matched >= gt_count:
                stats["true_positives"] += gt_count
                stats["false_positives"] += max(0, len(findings) - gt_count)
            elif matched > 0:
                stats["true_positives"] += matched
                stats["false_negatives"] += (gt_count - matched)
                stats["false_positives"] += unmatched
            else:
                stats["false_negatives"] += gt_count
                stats["false_positives"] += len(findings)

            stats["by_type"][gt_type]["tp"] += matched
            stats["by_type"][gt_type]["fp"] += unmatched
            stats["by_type"][gt_type]["fn"] += max(0, gt_count - matched)

            for f in findings:
                sev = f.get("severity", "low")
                stats["by_severity"][sev] += 1

            stats["per_sample"].append({
                "sample": sample,
                "gt_type": gt_type,
                "gt_count": gt_count,
                "found": len(findings),
                "matched": matched,
                "cve": gt.get("cve_id", ""),
            })

        return stats

    def summary(self, stats: dict) -> str:
        tp = stats["true_positives"]; fp = stats["false_positives"]
        fn = stats["false_negatives"]
        precision = tp / max(tp + fp, 1)
        recall = tp / max(tp + fn, 1)
        f1 = 2 * precision * recall / max(precision + recall, 1e-9)

        lines = [
            f"Total samples: {stats['total_samples']}",
            f"Findings: {stats['total_findings']}",
            f"TP={tp} FP={fp} FN={fn}",
            f"Precision={precision:.3f} Recall={recall:.3f} F1={f1:.3f}",
        ]
        for vtype, vstats in sorted(stats["by_type"].items()):
            t,fp_count,fn_count = vstats["tp"],vstats["fp"],vstats["fn"]
            lines.append(f"  {vtype}: TP={t} FP={fp_count} FN={fn_count}")
        return "\n".join(lines)

    def to_json(self, stats: dict, output_path: str):
        with open(output_path, "w") as f:
            json.dump(stats, f, indent=2, default=str)


if __name__ == "__main__":
    parser = ResultParser({
        "cve_2014_0160": {"cve_id":"CVE-2014-0160","vuln_type":"buffer_overflow","vuln_count":1},
        "cve_2015_0235": {"cve_id":"CVE-2015-0235","vuln_type":"buffer_overflow","vuln_count":1},
    })
    # dummy data for testing
    test_results = [
        {"sample_name":"cve_2014_0160","findings":[{"type":"buffer_overflow","severity":"critical"}]},
        {"sample_name":"cve_2015_0235","findings":[]},
    ]
    stats = parser.parse(test_results)
    print(parser.summary(stats))
