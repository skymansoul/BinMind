# 结果收集与对比模块 — 汇总扫描结果，计算检出率/误报率/召回率
"""结果收集与对比模块。

从 scan_results/ 读取各样本的JSON结果，计算:
  - 检出率 (TP / (TP + FN)) = 召回率
  - 误报率 (FP / (TP + FP))
  - 精确率 (TP / (TP + FP))
  - 平均扫描用时

按漏洞类型分组统计，输出 markdown 表格 + JSON 汇总。

用法:
  python tests/collect_results.py                    # 生成汇总报告
  python tests/collect_results.py --format markdown  # 仅输出markdown
  python tests/collect_results.py --format json      # 仅输出JSON
"""

import os, sys, json, argparse
from pathlib import Path
from collections import defaultdict
from typing import List, Dict

SCAN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan_results")

# 已知的 ground truth: 哪些样本是真正的堆溢出漏洞
# 格式: sample_dir_name → expected_vuln_type
GROUND_TRUTH = {
    "CVE-2015-0235_ghost_heap_overflow": "heap_overflow",
    "CVE-2016-10191_heap_overflow": "heap_overflow",
    "CVE-2018-1000001_glibc_realpath_heap_overflow": "heap_overflow",
    "CVE-2021-3156_sudo_heap_overflow": "heap_overflow",
    "CVE-2023-27997_fortigate_heap_overflow": "heap_overflow",
    "CVE-2024-21626_runc_heap_overflow": "heap_overflow",
    "CVE-2022-0847_dirty_pipe": "heap_overflow",
    "CVE-2017-18017_tcp_mss": "heap_overflow",
    "CVE-2019-11477_tcp_sack": "heap_overflow",
    "CVE-2016-4971_wget": "heap_overflow",
    # 2025 堆溢出正样本
    "CVE-2025-TP001_tainted_heap_overflow": "heap_overflow",
    "CVE-2025-TP002_unbounded_heap_overflow": "heap_overflow",
    "CVE-2025-TP003_loop_bound": "heap_overflow",
    "CVE-2025-TP004_off_by_one": "heap_overflow",
    "CVE-2025-TP005_calc_error": "heap_overflow",
    "CVE-2025-TP006_direct_taint": "heap_overflow",
    "CVE-2025-TP007_cross_func_alloc": "heap_overflow",
    "CVE-2025-TP008_mul_size": "heap_overflow",
    "CVE-2025-TP009_indirect_taint": "heap_overflow",
    "CVE-2025-TP010_loop_write": "heap_overflow",
    "CVE-2025-TP011_call_ret_size": "heap_overflow",
    "CVE-2025-TP012_realloc_expand": "heap_overflow",
    "CVE-2025-TP013_struct_field": "heap_overflow",
    "CVE-2025-TP014_array_idx": "heap_overflow",
    "CVE-2025-TP015_chained_arith": "heap_overflow",
    "CVE-2025-TP016_strlen_offby": "heap_overflow",
    # 2025 堆溢出安全样本(应被过滤)
    "CVE-2025-FP001_constant_malloc_safe": "safe",
    "CVE-2025-FP002_guarded_malloc_safe": "safe",
    "CVE-2025-FP003_alignment_safe": "safe",
    "CVE-2025-FP004_and_mask_guard": "safe",
    "CVE-2025-FP005_loop_bound_safe": "safe",
    "CVE-2025-FP006_minsize_guard": "safe",
    "CVE-2025-FP007_cross_call_valid": "safe",
    "CVE-2025-FP008_cmova_capped": "safe",
    # UAF
    "CVE-2019-10149_uaf_exim": "uaf",
    "CVE-2019-15947_uaf": "uaf",
    "CVE-2020-10713_uaf_grub2": "uaf",
    "CVE-2022-0185_uaf_filesystem": "uaf",
    "CVE-2023-0597_uaf_netfilter": "uaf",
    "CVE-2024-1086_uaf_nf_tables": "uaf",
    # Format string
    "CVE-2012-0809_format_string": "format_string",
    # Stack overflow
    "CVE-2020-10757_stack_overflow": "stack_overflow",
    # Other
    "CVE-2014-0160_heartbleed": "buffer_overread",
    "CVE-2024-21887_cmd_inject": "cmd_injection",
}

# 动态生成新增FMT/IO样本的ground truth (保持代码精简)
for _d in os.listdir(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                  'cve_samples')):
    if _d.startswith('CVE-2025-FMT-TP'):
        GROUND_TRUTH[_d] = 'format_string'
    elif _d.startswith('CVE-2025-FMT-FP'):
        GROUND_TRUTH[_d] = 'safe'
    elif _d.startswith('CVE-2025-IO-TP'):
        GROUND_TRUTH[_d] = 'int_overflow'
    elif _d.startswith('CVE-2025-IO-FP'):
        GROUND_TRUTH[_d] = 'safe'


def load_scan_results() -> List[Dict]:
    """加载所有扫描结果JSON文件。"""
    results = []
    if not os.path.isdir(SCAN_DIR):
        return results
    for fname in sorted(os.listdir(SCAN_DIR)):
        if fname == "scan_summary.json":
            continue
        fpath = os.path.join(SCAN_DIR, fname)
        if fpath.endswith('.json'):
            try:
                with open(fpath, encoding='utf-8') as f:
                    results.append(json.load(f))
            except (json.JSONDecodeError, IOError, UnicodeDecodeError):
                pass
    return results


def compute_metrics(results: List[Dict]) -> Dict:
    """计算检出率/误报率/精确率。

    利用GROUND_TRUTH表判定是TP还是FP。
    """
    metrics = {
        'total_samples': len(results),
        'by_vuln_type': defaultdict(lambda: {
            'total': 0, 'detected': 0, 'missed': 0,
            'avg_tp': 0.0, 'avg_fp': 0.0, 'avg_time': 0.0,
        }),
        'overall': {
            'tp_samples': 0,    # 正确检出的样本数
            'fn_samples': 0,    # 漏报的样本数
            'fp_alerts': 0,     # 误报告警总数
            'tp_alerts': 0,     # 正确告警总数
            'total_alerts': 0,
            'avg_time': 0.0,
        },
    }

    total_time = 0.0
    for r in results:
        sample_name = r.get('sample', '')
        expected = GROUND_TRUTH.get(sample_name, 'unknown')
        vuln_type = r.get('vuln_type', expected)

        by_type = metrics['by_vuln_type'][vuln_type]
        by_type['total'] += 1
        by_type['avg_tp'] += r.get('tp_count', 0)
        by_type['avg_fp'] += r.get('fp_count', 0)
        by_type['avg_time'] += r.get('time_secs', 0)

        if r.get('detected'):
            by_type['detected'] += 1
            if vuln_type == expected:
                metrics['overall']['tp_samples'] += 1
        else:
            by_type['missed'] += 1
            if expected != 'unknown' and vuln_type == expected:
                metrics['overall']['fn_samples'] += 1

        metrics['overall']['tp_alerts'] += r.get('tp_count', 0)
        metrics['overall']['fp_alerts'] += r.get('fp_count', 0)
        metrics['overall']['total_alerts'] += r.get('findings_count', 0)
        total_time += r.get('time_secs', 0)

    # 计算平均值
    for vt, data in metrics['by_vuln_type'].items():
        if data['total'] > 0:
            data['avg_tp'] = round(data['avg_tp'] / data['total'], 2)
            data['avg_fp'] = round(data['avg_fp'] / data['total'], 2)
            data['avg_time'] = round(data['avg_time'] / data['total'], 2)

    if metrics['overall']['total_alerts'] > 0:
        metrics['overall']['fp_rate'] = round(
            metrics['overall']['fp_alerts'] / metrics['overall']['total_alerts'] * 100, 1)
    else:
        metrics['overall']['fp_rate'] = 0.0

    total_possible = metrics['overall']['tp_samples'] + metrics['overall']['fn_samples']
    if total_possible > 0:
        metrics['overall']['recall'] = round(
            metrics['overall']['tp_samples'] / total_possible * 100, 1)
    else:
        metrics['overall']['recall'] = 0.0

    metrics['overall']['avg_time'] = round(
        total_time / len(results), 2) if results else 0.0

    # Convert defaultdict to regular dict for JSON serialization
    metrics['by_vuln_type'] = dict(metrics['by_vuln_type'])
    return metrics


def format_markdown(metrics: Dict) -> str:
    """生成markdown格式报告。"""
    lines = [
        "# Heap Overflow Detection — Regression Test Report",
        "",
        f"**Total samples:** {metrics['total_samples']}",
        f"**Recall (检出率):** {metrics['overall']['recall']}%",
        f"**FP rate (误报率):** {metrics['overall']['fp_rate']}%",
        f"**Average scan time:** {metrics['overall']['avg_time']}s",
        "",
        "## By Vulnerability Type",
        "",
        "| Type | Samples | Detected | Missed | Avg TP | Avg FP | Avg Time |",
        "|------|---------|----------|--------|--------|--------|----------|",
    ]

    for vt, data in sorted(metrics['by_vuln_type'].items()):
        lines.append(
            f"| {vt} | {data['total']} | {data['detected']} | "
            f"{data['missed']} | {data['avg_tp']} | {data['avg_fp']} | "
            f"{data['avg_time']}s |")

    lines.extend([
        "",
        "## Phase Contribution Breakdown",
        "",
        "FP reduction by stage:",
        "- **Phase 1 (constant_size_filtered):** malloc(常量) → 立即过滤",
        "- **Phase 3 (path_infeasible_filtered):** 路径不可行 → 过滤",
        "- **Phase 4 (alignment_filtered):** glibc对齐约束 → 过滤",
        "- **Phase 2 (interval_filtered):** 区间约束矛盾 → 过滤",
        "",
    ])

    return '\n'.join(lines)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--format", choices=["markdown", "json", "all"],
                   default="all")
    args = p.parse_args()

    results = load_scan_results()
    if not results:
        print(f"No scan results found in {SCAN_DIR}")
        print("Run 'python tests/run_scanner.py' first.")
        return 1

    metrics = compute_metrics(results)

    if args.format in ("json", "all"):
        out_path = os.path.join(SCAN_DIR, "metrics_summary.json")
        with open(out_path, 'w', encoding='utf-8') as f:
            json.dump(metrics, f, indent=2, ensure_ascii=False)
        print(f"JSON saved to {out_path}")

    if args.format in ("markdown", "all"):
        md = format_markdown(metrics)
        out_path = os.path.join(SCAN_DIR, "regression_report.md")
        with open(out_path, 'w', encoding='utf-8') as f:
            f.write(md)
        print(f"Markdown report saved to {out_path}")
        print(md)

    return 0


if __name__ == "__main__":
    sys.exit(main())
