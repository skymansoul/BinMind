"""
回归测试 — 一键入口.

执行链路: 编译全部样本 → HFP 扫描 → 基线对比 → 收集报告 →
输出 JSON/CSV 与汇总. 退出码: 0=成功, 1=存在编译失败.

  python -m regression.run_regression
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from .sample_compiler import compile_and_summarize
from .scan_scheduler import ScanScheduler, summarize
from .result_collector import (build_comparison_rows, aggregate_comparison,
                               write_csv_report, write_json_report)
from .baseline_detector import baseline_scan_all

BASE = Path(__file__).resolve().parent.parent


def main() -> int:
    # 1. 编译
    manifest = compile_and_summarize()
    print(f"[compile] ok={manifest['ok']}/{manifest['total']} "
          f"failed={manifest['failed']}")

    # 2. HFP 扫描
    sched = ScanScheduler()
    results = sched.scan_manifest(manifest)
    stats = summarize(results)

    # 3. 基线对比
    asm_files = [r for r in manifest.get('asm_files', [])]
    baseline_map = baseline_scan_all(asm_files)
    rows = build_comparison_rows(results, baseline_map)
    agg = aggregate_comparison(rows)

    # 4. 报告
    report = {
        'compile': manifest,
        'hfp_stats': stats,
        'comparison': agg,
        'rows': rows,
    }
    json_path = write_json_report(report)
    csv_path = write_csv_report(rows)
    print(f"[report] json={json_path}")
    print(f"[report] csv={csv_path}")
    print(f"[metrics] recall={agg.get('hfp_recall')} "
          f"fpr={agg.get('hfp_fpr')} "
          f"fpr_reduction={agg.get('fpr_reduction_pct')}%")
    return 0 if manifest['ok'] == manifest['total'] else 1


if __name__ == '__main__':
    sys.exit(main())