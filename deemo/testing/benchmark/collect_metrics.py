# 统一指标收集 —— 从四工具扫描结果汇总检出率/耗时/内存/误报。
# 创建: 2026-08-14

import json, time, os
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ToolMetrics:
    tool_name: str
    total: int = 0
    detections: int = 0
    false_positives: int = 0
    avg_time_sec: float = 0.0
    peak_memory_mb: float = 0.0
    detection_rate: float = 0.0
    false_positive_rate: float = 0.0


def collect_all_metrics(our_results: list,
                         angr_results=None,
                         qemu_results=None,
                         ghidra_results=None) -> dict:
    """汇总所有工具的对比指标。"""
    report = {}

    report["our"] = _compute_metrics("BinMind (本工具)", our_results)

    if angr_results:
        report["angr"] = _compute_metrics("Angr", angr_results)
    else:
        report["angr"] = _placeholder("Angr")

    if qemu_results:
        report["qemu"] = _compute_metrics("QEMU user", qemu_results)
    else:
        report["qemu"] = _placeholder("QEMU user")

    if ghidra_results:
        report["ghidra"] = _compute_metrics("Ghidra", ghidra_results)
    else:
        report["ghidra"] = _placeholder("Ghidra")

    return report


def _compute_metrics(tool_name: str, results: list) -> dict:
    """从ScanResult列表计算指标。"""
    total = len(results)
    if total == 0:
        return {"tool": tool_name, "total": 0, "detections": 0,
                "avg_time_sec": 0, "detection_rate": 0}

    detections = sum(1 for r in results
                    if hasattr(r, 'success') and r.success
                    and ('FINDING' in (r.stdout or '') or '漏洞' in (r.stdout or '')))
    times = [getattr(r, 'duration_sec', 0) for r in results if r.success]
    avg_time = sum(times) / max(len(times), 1)

    return {
        "tool": tool_name,
        "total": total,
        "detections": detections,
        "false_positives": 0,  # 需从result_parser获取
        "avg_time_sec": round(avg_time, 2),
        "peak_memory_mb": 0,   # 需 /usr/bin/time -v 或 tracemalloc
        "detection_rate": round(detections / total, 3),
        "false_positive_rate": 0.0,
    }


def _placeholder(tool_name: str) -> dict:
    return {"tool": tool_name, "total": 0, "detections": 0,
            "avg_time_sec": 0, "detection_rate": 0,
            "note": "未安装或未配置, 需要单独运行"}


def generate_latex_table(report: dict,
                          packed_report: dict = None) -> str:
    """从指标字典生成LaTeX对比表格, 含加壳/未加壳分组。"""
    tools = [v for v in report.values() if isinstance(v, dict)]
    if not tools:
        return "% No data"

    header = (
        r"\begin{table}[htbp]" "\n"
        r"\centering" "\n"
        r"\caption{横向对比实验结果}" "\n"
        r"\label{tab:benchmark}" "\n"
        r"\begin{tabular}{lcccccc}" "\n"
        r"\toprule" "\n"
        r"工具 & 样本数 & 检出率 & 误报率 & 平均耗时(s) & 峰值内存(MB) & 分组 \\" "\n"
        r"\midrule" "\n"
    )
    rows = ""
    for t in tools:
        rows += (
            f"{t.get('tool', 'N/A')} & {t.get('total', 0)} & "
            f"{t.get('detection_rate', 0):.1%} & "
            f"{t.get('false_positive_rate', 0):.1%} & "
            f"{t.get('avg_time_sec', 0):.1f} & "
            f"{t.get('peak_memory_mb', 0):.0f} & 未加壳 \\\\" "\n"
        )
    if packed_report:
        packed_tools = [v for v in packed_report.values() if isinstance(v, dict)]
        if packed_tools:
            rows += r"\midrule" "\n"
            for t in packed_tools:
                rows += (
                    f"{t.get('tool', 'N/A')} & {t.get('total', 0)} & "
                    f"{t.get('detection_rate', 0):.1%} & "
                    f"{t.get('false_positive_rate', 0):.1%} & "
                    f"{t.get('avg_time_sec', 0):.1f} & "
                    f"{t.get('peak_memory_mb', 0):.0f} & UPX加壳 \\\\" "\n"
                )
    footer = (
        r"\bottomrule" "\n"
        r"\end{tabular}" "\n"
        r"\end{table}" "\n"
    )
    return header + rows + footer


def generate_plots(report: dict, output_dir: str):
    """生成matplotlib柱状图。"""
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        print("  matplotlib未安装, 跳过图表生成")
        return

    tools = [v for v in report.values() if isinstance(v, dict)]
    names = [t.get('tool', 'N/A') for t in tools]
    rates = [t.get('detection_rate', 0) * 100 for t in tools]
    times = [t.get('avg_time_sec', 0) for t in tools]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4))

    # 检出率柱状图
    colors = ['#2ecc71' if n.startswith('BinMind') else '#3498db' for n in names]
    ax1.bar(names, rates, color=colors)
    ax1.set_ylabel('Detection Rate (%)')
    ax1.set_title('Detection Rate by Tool')
    ax1.set_ylim(0, 100)
    for i, v in enumerate(rates):
        ax1.text(i, v + 1, f'{v:.0f}%', ha='center')

    # 平均耗时柱状图
    ax2.bar(names, times, color=colors)
    ax2.set_ylabel('Avg Time (sec)')
    ax2.set_title('Average Scan Time per Sample')
    for i, v in enumerate(times):
        ax2.text(i, v + 0.5, f'{v:.1f}s', ha='center')

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'benchmark_comparison.png'), dpi=150)
    plt.close()
    print(f"  图表: {os.path.join(output_dir, 'benchmark_comparison.png')}")
