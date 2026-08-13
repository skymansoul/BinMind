"""
结果收集与对比模块 — 汇总扫描结果, 对比预期漏洞, 生成报告.

定义每个样本的ground truth(含漏洞/安全), 对比检测结果
计算检出率/误报率/漏报率.

创建: 2024-12-09
"""

from typing import Dict, List
from dataclasses import dataclass, field


# Ground truth: True=含漏洞(应检出), False=安全(不应报告)
GROUND_TRUTH = {
    "CVE_01": True, "CVE_02": True, "CVE_03": False,
    "CVE_04": True, "CVE_05": False, "CVE_06": True,
    "CVE_07": True, "CVE_08": True, "CVE_09": True,
    "CVE_10": True, "CVE_11": True, "CVE_12": True,
    "CVE_13": True, "CVE_14": True, "CVE_15": True,
    "CVE_16": False, "CVE_17": False, "CVE_18": False,
    "CVE_19": True, "CVE_20": True, "CVE_21": False, "CVE_22": True,
}


@dataclass
class SampleResult:
    sample_id: str
    has_vuln: bool
    detected: bool
    finding_count: int
    time_ms: float
    is_true_positive: bool = False
    is_false_positive: bool = False
    is_false_negative: bool = False
    stats: dict = field(default_factory=dict)


def evaluate_results(scan_results: List[Dict]) -> List[SampleResult]:
    """对比扫描结果与ground truth, 生成评估数据."""
    evaluated = []
    for r in scan_results:
        sid = r.get("sample_id", "")
        has_vuln = GROUND_TRUTH.get(sid, True)
        finding_count = len(r.get("findings", []))
        detected = finding_count > 0

        sr = SampleResult(
            sample_id=sid,
            has_vuln=has_vuln,
            detected=detected,
            finding_count=finding_count,
            time_ms=r.get("time_ms", 0),
            stats=r.get("stats", {}),
        )

        if has_vuln and detected:
            sr.is_true_positive = True
        elif not has_vuln and detected:
            sr.is_false_positive = True
        elif has_vuln and not detected:
            sr.is_false_negative = True

        evaluated.append(sr)

    return evaluated


def compute_metrics(results: List[SampleResult]) -> Dict:
    """计算总体指标: 召回率, 误报率, 精确率, F1."""
    tp = sum(1 for r in results if r.is_true_positive)
    fp = sum(1 for r in results if r.is_false_positive)
    fn = sum(1 for r in results if r.is_false_negative)
    tn = sum(1 for r in results if not r.has_vuln and not r.detected)

    total_vuln = tp + fn
    total_safe = tn + fp
    total = len(results)

    recall = tp / total_vuln if total_vuln > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    fpr = fp / total_safe if total_safe > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) \
        if (precision + recall) > 0 else 0
    avg_time = sum(r.time_ms for r in results) / total if total > 0 else 0

    return {
        "true_positive": tp,
        "false_positive": fp,
        "false_negative": fn,
        "true_negative": tn,
        "recall": round(recall, 4),
        "precision": round(precision, 4),
        "false_positive_rate": round(fpr, 4),
        "f1_score": round(f1, 4),
        "avg_time_ms": round(avg_time, 2),
        "total_samples": total,
    }


def format_report(results: List[SampleResult],
                  metrics: Dict) -> str:
    """生成文本报告."""
    lines = []
    lines.append("=" * 70)
    lines.append("堆溢出检测回归测试报告 (DDSSC)")
    lines.append("=" * 70)
    lines.append("")

    lines.append(f"{'样本':<12} {'含漏洞':<8} {'检出':<8} "
                 f"{'告警数':<8} {'耗时ms':<10} {'判定'}")
    lines.append("-" * 70)

    for r in results:
        vuln_str = "是" if r.has_vuln else "否"
        det_str = "是" if r.detected else "否"
        if r.is_true_positive:
            verdict = "TP"
        elif r.is_false_positive:
            verdict = "FP(误报)"
        elif r.is_false_negative:
            verdict = "FN(漏报)"
        else:
            verdict = "TN"
        lines.append(
            f"{r.sample_id:<12} {vuln_str:<8} {det_str:<8} "
            f"{r.finding_count:<8} {r.time_ms:<10.2f} {verdict}")

    lines.append("-" * 70)
    lines.append(f"召回率(Recall):     {metrics['recall']:.2%}")
    lines.append(f"精确率(Precision): {metrics['precision']:.2%}")
    lines.append(f"误报率(FPR):       {metrics['false_positive_rate']:.2%}")
    lines.append(f"F1分数:            {metrics['f1_score']:.4f}")
    lines.append(f"平均耗时:          {metrics['avg_time_ms']:.2f} ms")
    lines.append(f"TP={metrics['true_positive']} "
                 f"FP={metrics['false_positive']} "
                 f"FN={metrics['false_negative']} "
                 f"TN={metrics['true_negative']}")
    lines.append("")

    for r in results:
        if r.stats and "ddssc_filter" in r.stats:
            lines.append(f"\n{r.sample_id} DDSSC统计:")
            ddssc = r.stats["ddssc_filter"]
            for k, v in ddssc.items():
                lines.append(f"  {k}: {v}")

    return "\n".join(lines)


if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.dirname(__file__))
    from sample_compiler import compile_all
    from scan_scheduler import scan_all

    compile_all()
    raw = scan_all()
    evaluated = evaluate_results(raw)
    metrics = compute_metrics(evaluated)
    report = format_report(evaluated, metrics)
    print(report)

__all__ = ["evaluate_results", "compute_metrics", "format_report",
           "GROUND_TRUTH", "SampleResult"]
