#!/usr/bin/env python3
"""
堆溢出检测回归测试 — 一键运行入口.

流程: 编译样本 → 扫描检测 → 收集结果 → 输出报告.

创建: 2026-06-02
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# 上溯到deemo/使modules包可导入: regression_heap→tests→vuln→modules→deemo
sys.path.insert(0, os.path.abspath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "..")))

from sample_compiler import compile_all
from scan_scheduler import scan_all
from result_collector import evaluate_results, compute_metrics, format_report


def main():
    print("[1/3] 编译样本...")
    compile_results = compile_all()
    ok = sum(1 for r in compile_results if r["success"])
    print(f"  编译成功: {ok}/{len(compile_results)}")

    print("\n[2/3] 扫描检测...")
    scan_results = scan_all()
    total_findings = sum(len(r["findings"]) for r in scan_results)
    print(f"  扫描完成: {len(scan_results)} 样本, "
          f"共 {total_findings} 条告警")

    print("\n[3/3] 生成报告...")
    evaluated = evaluate_results(scan_results)
    metrics = compute_metrics(evaluated)
    report = format_report(evaluated, metrics)
    print(report)

    report_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "regression_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"\n报告已保存至: {report_path}")

    return metrics


if __name__ == "__main__":
    main()
