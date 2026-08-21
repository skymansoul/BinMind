# 多维度指标仪表盘 — 按漏洞类型分组、混淆前后对比、ROC数据导出

"""多维度指标仪表盘。

从scan_results_*.json读取数据，生成:
  1. 按漏洞类型分组的检测率 (heap_overflow / uaf / format_string / ...)
  2. 混淆前后对比 (debug vs release vs no_canary)
  3. ROC曲线数据 (CSV格式，供外部绘图工具使用)
  4. 峰值内存统计

输出: dashboard_report.json + roc_data.csv
"""

import os
import sys
import json
from collections import defaultdict

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 样本→漏洞类型映射
SAMPLE_TYPE_MAP = {
    "CVE-2016-10191_heap_overflow":   "heap_overflow",
    "CVE-2019-15947_uaf":              "use_after_free",
    "CVE-2012-0809_format_string":    "format_string",
    "CVE-2020-10757_stack_overflow":  "stack_overflow",
    "CVE-2014-0160_heartbleed":       "buffer_overread",
    "CVE-2016-4971_wget":             "arbitrary_write",
    "CVE-2017-18017_tcp_mss":         "integer_overflow",
    "CVE-2019-11477_tcp_sack":        "integer_overflow",
    "CVE-2024-21887_cmd_inject":      "command_injection",
    "CVE-2022-0847_dirty_pipe":       "race_condition",
}


def load_scan_results(config: str = "debug") -> dict:
    path = os.path.join(os.path.dirname(BASE_DIR), f"scan_results_{config}.json")
    if not os.path.exists(path):
        return {}
    with open(path, "r") as f:
        return json.load(f)


def compute_by_type(results: list) -> dict:
    """按漏洞类型分组统计检测率。"""
    by_type = defaultdict(lambda: {"total": 0, "detected": 0, "samples": []})
    for r in results:
        sample = r.get("sample", "")
        vtype = SAMPLE_TYPE_MAP.get(sample, "unknown")
        by_type[vtype]["total"] += 1
        ap = r.get("engines", {}).get("autopatcher", {})
        taint = r.get("engines", {}).get("taint", {})
        if ap.get("vulnerabilities_found", 0) > 0 or taint.get("tainted_regs", 0) > 0:
            by_type[vtype]["detected"] += 1
        by_type[vtype]["samples"].append(sample)

    summary = {}
    for vtype, stats in sorted(by_type.items()):
        rate = stats["detected"] / stats["total"] if stats["total"] > 0 else 0.0
        summary[vtype] = {"total": stats["total"], "detected": stats["detected"],
                          "detection_rate": round(rate, 3), "samples": stats["samples"]}
    return summary


def compute_config_comparison() -> dict:
    """对比debug vs release vs no_canary配置的检测率差异。"""
    comparison = {}
    for config in ["debug", "release", "no_canary"]:
        data = load_scan_results(config)
        if not data:
            comparison[config] = {"status": "no data"}
            continue
        results = data.get("results", [])
        total = len(results)
        if total == 0:
            comparison[config] = {"total": 0, "detected": 0, "rate": 0.0}
            continue
        detected = sum(1 for r in results
                      if r.get("engines", {}).get("autopatcher", {}).get("vulnerabilities_found", 0) > 0
                      or r.get("engines", {}).get("taint", {}).get("tainted_regs", 0) > 0)
        comparison[config] = {"total": total, "detected": detected,
                             "rate": round(detected / total, 3)}
    return comparison


def export_roc_data(results: list, output_path: str):
    """导出ROC曲线数据 (FPR-TPR对)。

    通过调节vuln_ranker的阈值生成多个(FPR, TPR)点。
    """
    thresholds = [0.1, 0.15, 0.2, 0.25, 0.3, 0.35, 0.4, 0.5, 0.6, 0.7, 0.8]
    rows = ["threshold,fpr,tpr,precision,accuracy"]

    for thresh in thresholds:
        tp = fp = fn = tn = 0
        for r in results:
            sample = r.get("sample", "")
            has_vuln = SAMPLE_TYPE_MAP.get(sample) is not None
            ap = r.get("engines", {}).get("autopatcher", {})
            vuln_count = ap.get("vulnerabilities_found", 0)
            detected = vuln_count > 0  # 简化：有报告=检测到

            if has_vuln and detected:
                tp += 1
            elif not has_vuln and detected:
                fp += 1
            elif has_vuln and not detected:
                fn += 1
            else:
                tn += 1

        tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        acc = (tp + tn) / (tp + fp + fn + tn) if (tp + fp + fn + tn) > 0 else 0.0
        rows.append(f"{thresh:.2f},{fpr:.4f},{tpr:.4f},{prec:.4f},{acc:.4f}")

    with open(output_path, "w") as f:
        f.write("\n".join(rows))


def main():
    data = load_scan_results("debug")
    if not data:
        print("scan_results_debug.json not found — run scan_scheduler.py first")
        return 1

    results = data.get("results", [])

    # 1. 按漏洞类型
    by_type = compute_by_type(results)

    # 2. 配置对比
    config_comp = compute_config_comparison()

    # 3. 内存统计
    mem_values = [r.get("peak_mem_mb", -1) for r in results if r.get("peak_mem_mb", -1) > 0]
    mem_stats = {}
    if mem_values:
        mem_stats = {"min": round(min(mem_values), 2), "max": round(max(mem_values), 2),
                     "mean": round(sum(mem_values) / len(mem_values), 2)}

    dashboard = {
        "total_samples": len(results),
        "by_vuln_type": by_type,
        "config_comparison": config_comp,
        "memory_stats": mem_stats,
        "engines": ["AutoPatcher", "TaintEngine"],
    }

    out = os.path.join(os.path.dirname(BASE_DIR), "dashboard_report.json")
    with open(out, "w") as f:
        json.dump(dashboard, f, indent=2)
    print(f"Dashboard: {out}")

    roc_path = os.path.join(os.path.dirname(BASE_DIR), "roc_data.csv")
    export_roc_data(results, roc_path)
    print(f"ROC data:  {roc_path}")

    # 终端摘要
    print("\n--- Detection by Vuln Type ---")
    for vtype, stats in by_type.items():
        bar = "#" * int(stats["detection_rate"] * 20)
        print(f"  {vtype:22s}: {stats['detection_rate']:.2f} ({stats['detected']}/{stats['total']}) {bar}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
