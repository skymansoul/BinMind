# 横向对比实验主调度器
# 将同一批样本喂给各工具, 统计检测耗时/误报/漏报/峰值内存.
# 创建: 2026-08-05

import os, sys, json, time, subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional

@dataclass
class ToolResult:
    tool: str
    sample: str
    vuln_type: str
    elapsed_ms: float = 0.0
    peak_memory_kb: int = 0
    detected: bool = False
    false_positive: bool = False
    error: str = ""

@dataclass
class ComparisonReport:
    tool_name: str
    total_samples: int
    detected: int
    missed: int
    false_positives: int
    avg_time_ms: float
    avg_memory_kb: int
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0

def run_tool(tool_cmd: List[str], binary_path: str, timeout_sec: int = 120) -> ToolResult:
    """调用外部工具并收集指标."""
    t0 = time.time()
    try:
        proc = subprocess.run(
            tool_cmd + [binary_path],
            capture_output=True, text=True, timeout=timeout_sec)
        elapsed = (time.time() - t0) * 1000
        detected = "VULN" in proc.stdout.upper() or "FINDING" in proc.stdout.upper()
        return ToolResult(tool=tool_cmd[0], sample=os.path.basename(binary_path),
                          vuln_type="unknown", elapsed_ms=elapsed, detected=detected)
    except subprocess.TimeoutExpired:
        return ToolResult(tool=tool_cmd[0], sample=os.path.basename(binary_path),
                          vuln_type="unknown", elapsed_ms=timeout_sec*1000,
                          error="timeout")
    except FileNotFoundError:
        return ToolResult(tool=tool_cmd[0], sample=os.path.basename(binary_path),
                          vuln_type="unknown", error="tool_not_found")

def compute_metrics(results: List[ToolResult], ground_truth: Dict[str,str]) -> ComparisonReport:
    """从原始结果计算检测指标."""
    tool = results[0].tool if results else "unknown"
    n = len(results)
    tp = sum(1 for r in results if r.detected and ground_truth.get(r.sample) == r.vuln_type)
    fp = sum(1 for r in results if r.detected and ground_truth.get(r.sample) != r.vuln_type)
    fn = sum(1 for r in results if not r.detected and ground_truth.get(r.sample) == r.vuln_type)
    avg_t = sum(r.elapsed_ms for r in results) / max(n, 1)
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-9)
    return ComparisonReport(tool_name=tool, total_samples=n,
                            detected=tp+fp, missed=fn, false_positives=fp,
                            avg_time_ms=avg_t, avg_memory_kb=0,
                            precision=precision, recall=recall, f1_score=f1)

def generate_latex_table(reports: List[ComparisonReport], output_path: str):
    """从报告生成LaTeX对比表格."""
    with open(output_path, "w") as f:
        f.write(r"\begin{table}[htbp]" + "\n")
        f.write(r"\caption{Cross-Tool Vulnerability Detection Comparison}" + "\n")
        f.write(r"\label{tab:compare}" + "\n")
        f.write(r"\begin{tabular}{lcccccc}" + "\n")
        f.write(r"\toprule" + "\n")
        f.write(r"Tool & Samples & Detected & Precision & Recall & F1 & Avg Time (ms) \\" + "\n")
        f.write(r"\midrule" + "\n")
        for r in reports:
            f.write(f"{r.tool_name} & {r.total_samples} & {r.detected} & "
                    f"{r.precision:.2f} & {r.recall:.2f} & {r.f1_score:.2f} & "
                    f"{r.avg_time_ms:.0f} \\\\\n")
        f.write(r"\bottomrule" + "\n")
        f.write(r"\end{tabular}" + "\n")
        f.write(r"\end{table}" + "\n")
    print(f"LaTeX table saved to {output_path}")

def run_all_comparisons(binary_dir: str, ground_truth: Dict[str,str],
                         output_dir: str = "experiments/output"):
    """运行全部对比实验: Angr, QEMU, Ghidra, OurTool."""
    os.makedirs(output_dir, exist_ok=True)

    tools = {
        "angr": ["python", "-m", "experiments.angr_adapter"],
        "qemu": ["python", "-m", "experiments.qemu_adapter"],
        "ghidra": ["python", "-m", "experiments.ghidra_adapter"],
        "ours": ["python", "-m", "tests.regression.scan_runner"],
    }

    all_results = {}
    for tool_name, cmd in tools.items():
        print(f"Running {tool_name}...")
        tool_results = []
        for fname in sorted(os.listdir(binary_dir)):
            fpath = os.path.join(binary_dir, fname)
            if not os.path.isfile(fpath): continue
            if os.path.splitext(fpath)[1] in (".c",".h",".py"): continue
            r = run_tool(cmd, fpath, timeout_sec=120)
            tool_results.append(r)
        all_results[tool_name] = tool_results
        report = compute_metrics(tool_results, ground_truth)
        print(f"  {report.tool_name}: P={report.precision:.2f} R={report.recall:.2f} F1={report.f1_score:.2f}")

    reports = [compute_metrics(all_results[t], ground_truth) for t in all_results]
    generate_latex_table(reports, os.path.join(output_dir, "comparison_table.tex"))

    with open(os.path.join(output_dir, "raw_results.json"), "w") as f:
        json.dump({t: [vars(r) for r in results] for t, results in all_results.items()}, f, indent=2)

    return reports

if __name__ == "__main__":
    bin_dir = os.path.join(os.path.dirname(__file__), "..", "tests", "regression", "binaries")
    gt = {
        "cve_2014_0160": "buffer_overflow", "cve_2015_0235": "buffer_overflow",
        "cve_2016_4484": "buffer_overflow", "cve_2017_7269": "buffer_overflow",
        "cve_2019_11477": "use_after_free",
    }
    if os.path.isdir(bin_dir):
        reports = run_all_comparisons(bin_dir, gt)
    else:
        print(f"No binaries at {bin_dir}. Run build_samples.py first.")
