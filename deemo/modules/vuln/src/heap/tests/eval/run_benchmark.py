"""堆区间证据消歧综合对比实验 — 基准运行器.

协调所有四个检测方法 (堆区间证据消歧 / Angr / QEMU / Ghidra),
运行全量对比, 汇总结果到统一 JSON.

用法:
  python run_benchmark.py              # 全量 (耗时较长)
  python run_benchmark.py --quick       # 快速模式 (仅堆区间证据消歧)

创建: 2024-12-09
"""
import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List


SCRIPTS_DIR = Path(__file__).resolve().parent
RESULTS_DIR = SCRIPTS_DIR.parent / "results"
RESULTS_DIR.mkdir(exist_ok=True)

TOOLS = {
    "shield": {
        "script": "run_scanner.py",
        "results": "scan_results.json",
        "description": "SHIELD — 三引擎 FP 消减 (本系统)",
    },
    "angr": {
        "script": "eval/angr_explorer.py",
        "results": "eval/angr_results.json",
        "description": "Angr — 符号执行 (USENIX 2016)",
    },
    "qemu": {
        "script": "eval/qemu_tracer.py",
        "results": "eval/qemu_results.json",
        "description": "QEMU — user-mode 动态追踪",
    },
    "ghidra": {
        "script": "eval/ghidra_headless.py",
        "results": "eval/ghidra_results.json",
        "description": "Ghidra — headless 反编译",
    },
}


def run_tool(name: str, info: dict, sample: str = "") -> bool:
    """运行单个工具."""
    script = SCRIPTS_DIR / info["script"]
    if not script.exists():
        print(f"  [SKIP] {name}: script not found ({script})")
        return False

    cmd = ["python", str(script)]
    if sample:
        cmd.extend(["--sample", sample])
    else:
        cmd.append("--all")

    print(f"  [{name}] Running: {' '.join(cmd)}")
    t0 = time.perf_counter()
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        elapsed = time.perf_counter() - t0
        if result.returncode != 0:
            print(f"  [{name}] FAILED ({elapsed:.0f}s): {result.stderr[-200:]}")
            return False
        print(f"  [{name}] OK ({elapsed:.0f}s)")
        return True
    except subprocess.TimeoutExpired:
        print(f"  [{name}] TIMEOUT")
        return False


def merge_results() -> dict:
    """合并所有工具的结果到统一格式."""
    summary = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "tools": {},
    }

    # 堆区间证据消歧 results
    shield_path = RESULTS_DIR / "scan_results.json"
    if shield_path.exists():
        with open(shield_path, encoding="utf-8") as f:
            shield_data = json.load(f)
        summary["tools"]["shield"] = {
            "description": TOOLS["shield"]["description"],
            "samples": len(shield_data),
            "total_findings_raw": sum(r.get('raw_count', 0) for r in shield_data),
            "total_findings_filtered": sum(r.get('final_count', 0) for r in shield_data),
            "avg_filter_rate": (
                sum(r.get('filtered_count', 0) for r in shield_data) /
                max(1, sum(r.get('raw_count', 0) for r in shield_data))
            ),
            "avg_time_ms": (
                sum(r.get('shield_time_ms', 0) for r in shield_data) / max(1, len(shield_data))
            ),
            "per_sample": [
                {
                    "name": r['sample'],
                    "raw": r['raw_count'],
                    "final": r['final_count'],
                    "filtered": r.get('filtered_count', 0),
                }
                for r in shield_data
            ],
        }

    # Angr results
    angr_path = RESULTS_DIR / "angr_results.json"
    if angr_path.exists():
        try:
            with open(angr_path, encoding="utf-8") as f:
                angr_data = json.load(f)
            if isinstance(angr_data, list):
                summary["tools"]["angr"] = {
                    "description": TOOLS["angr"]["description"],
                    "samples": len(angr_data),
                    "total_findings": sum(r.get('findings', 0) for r in angr_data),
                    "avg_time_ms": (
                        sum(r.get('time_ms', 0) for r in angr_data) / max(1, len(angr_data))
                    ),
                }
        except json.JSONDecodeError:
            summary["tools"]["angr"] = {"error": "invalid JSON"}

    # QEMU results
    qemu_path = RESULTS_DIR / "qemu_results.json"
    if qemu_path.exists():
        try:
            with open(qemu_path, encoding="utf-8") as f:
                qemu_data = json.load(f)
            if isinstance(qemu_data, list):
                summary["tools"]["qemu"] = {
                    "description": TOOLS["qemu"]["description"],
                    "samples": len(qemu_data),
                    "total_findings": sum(r.get('findings', 0) for r in qemu_data),
                    "avg_time_ms": (
                        sum(r.get('time_ms', 0) for r in qemu_data) / max(1, len(qemu_data))
                    ),
                }
        except json.JSONDecodeError:
            summary["tools"]["qemu"] = {"error": "invalid JSON"}

    # Ghidra results
    ghidra_path = RESULTS_DIR / "ghidra_results.json"
    if ghidra_path.exists():
        try:
            with open(ghidra_path, encoding="utf-8") as f:
                ghidra_data = json.load(f)
            if isinstance(ghidra_data, list):
                summary["tools"]["ghidra"] = {
                    "description": TOOLS["ghidra"]["description"],
                    "samples": len(ghidra_data),
                    "total_findings": sum(r.get('findings', 0) for r in ghidra_data),
                    "avg_time_ms": (
                        sum(r.get('time_ms', 0) for r in ghidra_data) / max(1, len(ghidra_data))
                    ),
                }
        except json.JSONDecodeError:
            summary["tools"]["ghidra"] = {"error": "invalid JSON or not configured"}

    return summary


def main():
    parser = argparse.ArgumentParser(description="SHIELD 基准测试运行器")
    parser.add_argument("--quick", action="store_true", help="仅运行 SHIELD (快速)")
    parser.add_argument("--sample", type=str, default="", help="单样本模式")
    parser.add_argument("--skip", type=str, default="", help="跳过的工具 (逗号分隔)")
    args = parser.parse_args()

    skip = set(s.strip() for s in args.skip.split(",") if s.strip())

    tools_to_run = ["shield"] if args.quick else list(TOOLS.keys())
    for name in tools_to_run:
        if name in skip:
            print(f"  [SKIP] {name} (requested)")
            continue
        run_tool(name, TOOLS[name], args.sample)

    # 合并 & 写入汇总
    summary = merge_results()
    summary_path = RESULTS_DIR / "benchmark_summary.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(f"\n  Benchmark summary: {summary_path}")

    # 打印简洁对比
    tools = summary.get("tools", {})
    print(f"\n  {'Tool':<20} {'Samples':>8} {'Findings':>10} {'Avg Time':>12}")
    print(f"  {'-'*20} {'-'*8} {'-'*10} {'-'*12}")
    for name, data in tools.items():
        if 'error' in data:
            print(f"  {name:<20} {'N/A':>8} {'N/A':>10} {'N/A':>12} [{data['error']}]")
        else:
            findings = data.get('total_findings', data.get('total_findings_filtered', 'N/A'))
            avg_time = f"{data.get('avg_time_ms', 0):.0f}ms"
            print(f"  {name:<20} {data.get('samples', 'N/A'):>8} {str(findings):>10} {avg_time:>12}")


if __name__ == "__main__":
    main()
