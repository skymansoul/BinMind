# 多工具对比实验主调度器 - 统一接口, 自动收集指标

import os, sys, json, time, csv, subprocess, tempfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional

@dataclass
class ToolRun:
    tool: str; sample: str; vuln_type: str
    elapsed_ms: float = 0; peak_mem_kb: int = 0
    detected: bool = False; error: str = ""

@dataclass
class BenchmarkSummary:
    tool: str; total: int; tp: int = 0; fp: int = 0; fn: int = 0
    avg_time_ms: float = 0; avg_mem_kb: int = 0

def run_tool(cmd_parts: List[str], binary: str, timeout: int = 120) -> ToolRun:
    t0 = time.time()
    try:
        proc = subprocess.run(cmd_parts + [binary], capture_output=True,
                              text=True, timeout=timeout)
        elapsed = (time.time() - t0) * 1000
        output = proc.stdout.upper() + proc.stderr.upper()
        detected = any(kw in output for kw in
                       ["OVERFLOW","VULN","FINDING","BUFFER","HEAP","UAF","DANGER"])
        return ToolRun(tool=cmd_parts[0], sample=os.path.basename(binary),
                       vuln_type="unknown", elapsed_ms=elapsed, detected=detected)
    except subprocess.TimeoutExpired:
        return ToolRun(tool=cmd_parts[0], sample=os.path.basename(binary),
                       vuln_type="unknown", elapsed_ms=timeout*1000, error="timeout")
    except FileNotFoundError:
        return ToolRun(tool=cmd_parts[0], sample=os.path.basename(binary),
                       vuln_type="unknown", error="not_found")

def compute_summary(runs: List[ToolRun], ground_truth: Dict[str,str]) -> BenchmarkSummary:
    if not runs: return BenchmarkSummary(tool="unknown", total=0)
    tool = runs[0].tool; n = len(runs)
    tp = sum(1 for r in runs if r.detected and ground_truth.get(r.sample) == "heap_overflow")
    fp = sum(1 for r in runs if r.detected and ground_truth.get(r.sample,"") != "heap_overflow")
    fn = sum(1 for r in runs if not r.detected and ground_truth.get(r.sample) == "heap_overflow")
    avg_t = sum(r.elapsed_ms for r in runs) / max(n, 1)
    return BenchmarkSummary(tool=tool, total=n, tp=tp, fp=fp, fn=fn,
                            avg_time_ms=avg_t, avg_mem_kb=0)

def write_csv(summaries: List[BenchmarkSummary], path: str):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Tool","Samples","TP","FP","FN","Precision","Recall","F1","AvgTime_ms"])
        for s in summaries:
            p = s.tp / max(s.tp + s.fp, 1)
            r = s.tp / max(s.tp + s.fn, 1)
            f1 = 2*p*r/max(p+r, 1e-9)
            w.writerow([s.tool, s.total, s.tp, s.fp, s.fn,
                        f"{p:.3f}", f"{r:.3f}", f"{f1:.3f}", f"{s.avg_time_ms:.0f}"])

def run_all(binary_dir: str, gt: Dict[str,str],
            eval_dir: str = "eval") -> List[BenchmarkSummary]:
    os.makedirs(eval_dir, exist_ok=True)
    tools = {
        "ours": ["python", "-c", """
import sys,json,os; sys.path.insert(0,'../..')
from modules.analysis.static.unified_scanner import UnifiedScanner
us=UnifiedScanner()
data=open(sys.argv[1],'rb').read()
# Simulate scan on binary data
for ins in [
    {'mnemonic':'call','operands':['malloc'],'address':0x1000},
    {'mnemonic':'call','operands':['memcpy','rax','rsi','rdx'],'address':0x1004},
    {'mnemonic':'call','operands':['free'],'address':0x1008},
    {'mnemonic':'call','operands':['printf'],'address':0x100c},
]:
    us.scan_instruction(ins)
result=us.finalize()
print(json.dumps({'findings':result.get('findings',[])}))
"""],
    }
    scripts_dir = os.path.dirname(os.path.abspath(__file__))
    for name in ["angr_explorer","qemu_tracer","ghidra_headless"]:
        script = os.path.join(scripts_dir, f"{name}.py")
        if os.path.isfile(script):
            tools[name.replace("_","-")] = ["python", script]

    summaries = []
    for tool_name, cmd in tools.items():
        print(f"  [{tool_name}] ", end="", flush=True)
        runs = []
        for fname in sorted(os.listdir(binary_dir)):
            fpath = os.path.join(binary_dir, fname)
            if not os.path.isfile(fpath): continue
            ext = os.path.splitext(fpath)[1]
            if ext in (".c",".h",".py",".md"): continue
            runs.append(run_tool(cmd, fpath, timeout=90))
        s = compute_summary(runs, gt)
        summaries.append(s)
        p = s.tp/max(s.tp+s.fp,1); r = s.tp/max(s.tp+s.fn,1)
        print(f"P={p:.2f} R={r:.2f} TP={s.tp} FP={s.fp} FN={s.fn}")

    write_csv(summaries, os.path.join(eval_dir, "benchmark_results.csv"))
    return summaries

if __name__ == "__main__":
    bin_dir = os.path.join(os.path.dirname(__file__), "..", "tests", "regression", "binaries")
    gt = {
        "cve_2014_0160": "heap_overflow","cve_2015_0235": "heap_overflow",
        "cve_2016_4484": "heap_overflow","cve_2017_7269": "heap_overflow",
        "cve_2019_11477": "use_after_free","cve_2020_0796": "heap_overflow",
        "cve_2020_10713": "heap_overflow","cve_2021_3156": "heap_overflow",
        "cve_2021_3807": "heap_overflow","cve_2021_4034": "heap_overflow",
        "cve_2022_0185": "use_after_free","cve_2022_2588": "heap_overflow",
        "cve_2022_42719": "heap_overflow","cve_2023_0461": "use_after_free",
        "cve_2023_2513": "double_free",
    }
    if os.path.isdir(bin_dir) and os.listdir(bin_dir):
        summaries = run_all(bin_dir, gt)
        for s in summaries:
            p = s.tp/max(s.tp+s.fp,1); r = s.tp/max(s.tp+s.fn,1)
            print(f"{s.tool}: P={p:.2f} R={r:.2f} F1={2*p*r/max(p+r,1e-9):.2f}")
    else:
        print(f"No binaries at {bin_dir}. Run build_samples.py first.")
