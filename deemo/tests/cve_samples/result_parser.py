# 创建: 2026-06-30 -- 结果解析+统计模块
import json, sys
from collections import Counter

def parse_results(scan_results_json):
    """解析扫描结果JSON, 输出统计.""" 
    if isinstance(scan_results_json, str):
        results = json.loads(scan_results_json)
    else:
        results = scan_results_json
    stats = {"total_binaries": len(results), "total_findings": 0,
             "by_type": Counter(), "by_cwe": Counter(),
             "avg_elapsed": 0.0, "filtered_count": 0}
    elapsed_total = 0.0
    for cve_id, info in results.items():
        findings = info.get("findings", [])
        stats["total_findings"] += len(findings)
        elapsed_total += info.get("elapsed_sec", 0)
        for f in findings:
            stats["by_type"][f.get("type", "unknown")] += 1
            stats["by_cwe"][f.get("cwe", "N/A")] += 1
            if f.get("filtered"):
                stats["filtered_count"] += 1
    if stats["total_binaries"] > 0:
        stats["avg_elapsed"] = round(elapsed_total / stats["total_binaries"], 2)
    return dict(stats)

def compute_detection_metrics(results, ground_truth):
    """计算检出率/误报率.
    ground_truth: {cve_id: expected_type} 期望的漏洞类型.
    """
    tp = fp = fn = 0
    for cve_id, expected in ground_truth.items():
        info = results.get(cve_id, {})
        findings = info.get("findings", [])
        types = [f.get("type") for f in findings if not f.get("filtered")]
        if any(expected in (t or "") for t in types):
            tp += 1
        elif len(findings) > 0:
            fp += 1  # 有发现但类型不匹配
        else:
            fn += 1  # 未发现
    total = tp + fp + fn
    return {
        "true_positives": tp, "false_positives": fp, "false_negatives": fn,
        "detection_rate": f"{tp/max(tp+fn,1)*100:.1f}%",
        "false_positive_rate": f"{fp/max(fp+tp,1)*100:.1f}%" if fp+tp > 0 else "0%",
        "total": total,
    }

if __name__ == "__main__":
    if len(sys.argv) > 1:
        with open(sys.argv[1]) as f:
            data = json.load(f)
        stats = parse_results(data)
        print(json.dumps(stats, indent=2))
    else:
        print("Usage: python result_parser.py <scan_results.json>")
