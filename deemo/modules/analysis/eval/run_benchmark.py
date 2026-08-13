# 多工具对比实验主控脚本 — BinMind vs Angr vs QEMU vs Ghidra
#
# 目标: 在堆溢出 CVE 样本 + 同源安全样本上, 统一输出
#   (工具名, 样本ID, 检出数, 误报数, 漏报数, 耗时, 峰值内存) CSV.
#
# 工具策略:
# BinMind: 本项目的堆溢出检测器 (含 AWSC 同源过滤), 真实运行.
#   - Angr:    angr CFGFast + capstone 调用点定位, 真实运行 (已安装).
#   - QEMU:    qemu-user 运行时追踪 (Windows 无 qemu → 优雅降级为
#              "不可用", 结果列留空并标注).
#   - Ghidra:  analyzeHeadless 无头分析 (无 GHIDRA_HOME → 优雅降级).
#
# 判定: 样本有 ground truth (is_vuln). 工具检出=至少1 finding:
#   vuln 样本检出 → TP; 未检出 → FN
#   safe 样本检出 → FP; 未检出 → TN
# 创建: 2026-06-15

import csv
import json
import sys
import time
import tracemalloc
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.heap_overflow_detect import HeapOverflowDetector
from modules.analysis.static.heap_alloc_model import AllocatorFamily

RESULTS_DIR = SCRIPT_DIR / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)


def run_binmind(binary: str) -> dict:
    """BinMind 堆检测器 (含 AWSC)."""
    t0 = time.perf_counter()
    tracemalloc.start()
    try:
        ins, fmt, main, ranges = disassemble_binary(binary)
        det = HeapOverflowDetector(AllocatorFamily.GLIBC,
                                   use_win64_abi="pei" in fmt.lower())
        if main:
            det.set_min_user_addr(main)
        if ranges:
            det.set_user_func_ranges(ranges)
        det.pre_analyze(ins)
        for i in ins:
            det.analyze_instruction(i)
        findings = det.finalize(ins)
        return {
            "tool": "BinMind", "detected": len(findings) > 0,
            "findings": len(findings),
            "time_ms": round((time.perf_counter() - t0) * 1000, 1),
            "peak_mb": round(tracemalloc.get_traced_memory()[0] / 1e6, 1),
            "error": "",
        }
    except Exception as e:
        return {"tool": "BinMind", "detected": False, "findings": 0,
                "time_ms": round((time.perf_counter() - t0) * 1000, 1),
                "peak_mb": 0, "error": str(e)[:120]}
    finally:
        tracemalloc.stop()


def run_angr(binary: str) -> dict:
    """Angr CFG+capstone 调用点定位."""
    t0 = time.perf_counter()
    try:
        from modules.analysis.eval.angr_explorer import analyze_binary
        r = analyze_binary(binary)
        return {
            "tool": "Angr", "detected": bool(r["detected"]),
            "findings": len(r["findings"]),
            "time_ms": round((time.perf_counter() - t0) * 1000, 1),
            "peak_mb": 0, "error": r.get("error", ""),
        }
    except Exception as e:
        return {"tool": "Angr", "detected": False, "findings": 0,
                "time_ms": round((time.perf_counter() - t0) * 1000, 1),
                "peak_mb": 0, "error": str(e)[:120]}


def run_qemu(binary: str) -> dict:
    """QEMU user mode + 插桩. Windows 无 qemu → 降级为不可用."""
    t0 = time.perf_counter()
    import shutil
    if not (shutil.which("qemu-x86_64")
            or shutil.which("qemu-x86_64-static")):
        return {"tool": "QEMU", "detected": False, "findings": 0,
                "time_ms": round((time.perf_counter() - t0) * 1000, 1),
                "peak_mb": 0, "error": "qemu unavailable"}
    try:
        import subprocess
        qemu = shutil.which("qemu-x86_64") or "qemu-x86_64-static"
        r = subprocess.run([qemu, "-strace", binary],
                           capture_output=True, text=True, timeout=20)
        crashed = any(s in r.stderr for s in
                      ("SIGSEGV", "SIGABRT", "SIGBUS", "SIGILL"))
        return {"tool": "QEMU", "detected": crashed, "findings": 1 if crashed else 0,
                "time_ms": round((time.perf_counter() - t0) * 1000, 1),
                "peak_mb": 0, "error": ""}
    except Exception as e:
        return {"tool": "QEMU", "detected": False, "findings": 0,
                "time_ms": round((time.perf_counter() - t0) * 1000, 1),
                "peak_mb": 0, "error": str(e)[:120]}


def run_ghidra(binary: str) -> dict:
    """Ghidra headless 函数名匹配审计. 无 GHIDRA_HOME → 降级."""
    t0 = time.perf_counter()
    import os
    ghome = os.environ.get("GHIDRA_HOME", "")
    if not ghome or not os.path.exists(
            os.path.join(ghome, "support", "analyzeHeadless")):
        return {"tool": "Ghidra", "detected": False, "findings": 0,
                "time_ms": round((time.perf_counter() - t0) * 1000, 1),
                "peak_mb": 0, "error": "GHIDRA_HOME unset"}
    try:
        from modules.analysis.eval.ghidra_headless import analyze_binary
        r = analyze_binary(binary)
        return {
            "tool": "Ghidra", "detected": bool(r["detected"]),
            "findings": len(r["findings"]),
            "time_ms": round((time.perf_counter() - t0) * 1000, 1),
            "peak_mb": 0, "error": r.get("error", ""),
        }
    except Exception as e:
        return {"tool": "Ghidra", "detected": False, "findings": 0,
                "time_ms": round((time.perf_counter() - t0) * 1000, 1),
                "peak_mb": 0, "error": str(e)[:120]}


TOOLS = {"BinMind": run_binmind, "Angr": run_angr,
         "QEMU": run_qemu, "Ghidra": run_ghidra}


def load_samples():
    """加载堆 CVE + AWSC 同源样本 (vuln/safe 配对)."""
    samples = []

    # 1) 堆 CVE 样本 (全为 vuln)
    awsc_manifest = Path("benchmark/samples_awsc/awsc_manifest.json")
    if awsc_manifest.exists():
        m = json.loads(awsc_manifest.read_text(encoding="utf-8"))
        for e in m:
            if e.get("compiled") and Path(e["binary"]).exists():
                samples.append({
                    "id": e["name"], "is_vuln": e["is_vuln"],
                    "binary": e["binary"], "group": "awsc_same_source",
                    "opt": e["opt"],
                })

    # 2) heap_fp_safe v2 (FP 倾向, vuln/safe 配对)
    fp_manifest = Path("benchmark/samples_heap_safe/"
                       "benchmark_fp_safe_v2_manifest.json")
    if fp_manifest.exists():
        m = json.loads(fp_manifest.read_text(encoding="utf-8"))
        for e in m:
            if e.get("compiled") and Path(e["binary"]).exists():
                samples.append({
                    "id": e["name"], "is_vuln": e["is_vuln"],
                    "binary": e["binary"], "group": "fp_prone",
                    "opt": e["opt"],
                })
    return samples


def main():
    samples = load_samples()
    print(f"comparison: {len(samples)} samples")

    rows = []
    for s in samples:
        for tool_name, runner in TOOLS.items():
            r = runner(s["binary"])
            r["sample"] = s["id"]
            r["is_vuln"] = s["is_vuln"]
            r["group"] = s["group"]
            r["opt"] = s["opt"]
            # 判定列: TP/FP/TN/FN (基于 ground truth 与检出)
            if s["is_vuln"]:
                r["verdict"] = "TP" if r["detected"] else "FN"
            else:
                r["verdict"] = "FP" if r["detected"] else "TN"
            rows.append(r)

    # CSV 输出
    csv_path = RESULTS_DIR / "multi_tool_comparison.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=[
            "tool", "sample", "is_vuln", "group", "opt", "verdict",
            "detected", "findings", "time_ms", "peak_mb", "error"])
        w.writeheader()
        w.writerows(rows)

    # 汇总按工具
    summary = {}
    for r in rows:
        tool = r["tool"]
        if tool not in summary:
            summary[tool] = {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "err": 0,
                             "time": 0, "n": 0}
        s_ = summary[tool]
        s_["n"] += 1
        s_["time"] += r["time_ms"]
        if r.get("error"):
            s_["err"] += 1
        if r["is_vuln"]:
            if r["detected"]:
                s_["tp"] += 1
            else:
                s_["fn"] += 1
        else:
            if r["detected"]:
                s_["fp"] += 1
            else:
                s_["tn"] += 1

    print("=" * 72)
    print(f"{'Tool':<10} TP  FP  TN  FN  Recall   Precision  FPR    Err")
    print("=" * 72)
    for tool, s_ in summary.items():
        tp, fp, fn = s_["tp"], s_["fp"], s_["fn"]
        recall = tp / max(tp + fn, 1)
        prec = tp / max(tp + fp, 1)
        fpr = fp / max(fp + s_["tn"], 1)
        print(f"{tool:<10} {tp:>2}  {fp:>2}  {s_['tn']:>2}  {fn:>2}  "
              f"{recall:.3f}     {prec:.3f}      {fpr:.3f}  {s_['err']:>2}")
        s_["recall"] = round(recall, 4)
        s_["precision"] = round(prec, 4)
        s_["fpr"] = round(fpr, 4)

    out = {"rows": rows, "summary": summary,
           "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}
    (RESULTS_DIR / "multi_tool_comparison.json").write_text(
        json.dumps(out, indent=2, ensure_ascii=False))
    print(f"\nCSV: {csv_path}")


if __name__ == "__main__":
    main()
