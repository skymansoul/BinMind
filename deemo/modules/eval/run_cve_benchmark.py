#!/usr/bin/env python3
"""统一多工具对比基准 — 20个CVE堆溢出样本集.

在 sample_bins/heap_overflow_cve 上运行:
  BinMind-DDSSC (本方法, Stage1-10完整管线)
  BinMind-Baseline (禁用AWSC/PcWBI精度阶段)
  angr (符号执行)
  Ghidra (静态审计)
  QEMU/Unicorn (动态追踪)

输出统一CSV: tool, sample, truth, verdict, findings, tp/fp/fn/tn,
             time_ms, peak_mem_mb.

用法: python run_cve_benchmark.py [--output results.csv]
创建: 2025-01-13
"""

import argparse
import csv
import json
import sys
import time
import tracemalloc
from pathlib import Path

ROOT = Path(__file__).resolve().parent
_BINMIND = Path(r"C:\Users\Administrator\Desktop\BinMind")
SAMPLE_DIR = (_BINMIND / "deemo" / "modules" / "vuln" / "sample_bins" /
              "heap_overflow_cve")

for p in (str(_BINMIND), str(_BINMIND / "deemo"), str(ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

# 20样本 ground truth: True=含漏洞, False=安全
VULN = {
    "CVE_01": True, "CVE_02": True, "CVE_03": False,
    "CVE_04": True, "CVE_05": False, "CVE_06": True,
    "CVE_07": True, "CVE_08": True, "CVE_09": True,
    "CVE_10": True, "CVE_11": True, "CVE_12": True,
    "CVE_13": True, "CVE_14": True, "CVE_15": True,
    "CVE_16": False, "CVE_17": False, "CVE_18": False,
    "CVE_19": True, "CVE_20": True,
}


def _load_module(name, path):
    import importlib.util
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run_binmind(binary, enhanced):
    from modules.analysis.static.disasm_util import disassemble_binary
    from modules.analysis.static.heap_overflow_detect import (
        HeapOverflowDetector)
    from modules.analysis.static.heap_alloc_model import AllocatorFamily
    from modules.analysis.static.import_resolver import resolve_call_targets

    instructions, fmt, main, ranges = disassemble_binary(binary)
    instructions = resolve_call_targets(binary, instructions, fmt)
    detector = HeapOverflowDetector(
        allocator_family=AllocatorFamily.GLIBC, use_win64_abi=True,
        enable_bwr=enhanced, enable_pcst=enhanced)
    detector.set_user_func_ranges(ranges)
    detector.pre_analyze(instructions)
    for ins in instructions:
        detector.analyze_instruction(ins)
    findings = detector.finalize(instructions)
    return {"findings": len(findings)}


def run_angr(binary):
    mod = _load_module("angr_explorer", ROOT / "angr_explorer.py")
    return mod.explore(binary)


def run_ghidra(binary):
    mod = _load_module("ghidra_headless", ROOT / "ghidra_headless.py")
    return mod.audit(binary)


def run_qemu(binary):
    mod = _load_module("qemu_tracer", ROOT / "qemu_tracer.py")
    return mod.trace(binary)


def verdict_of(is_vuln, count):
    if is_vuln and count > 0:
        return "TP"
    if is_vuln and count == 0:
        return "FN"
    if not is_vuln and count > 0:
        return "FP"
    return "TN"


def measure(fn):
    tracemalloc.start()
    t0 = time.perf_counter()
    try:
        r = fn()
        err = None
    except Exception as e:
        r = {"findings": 0}
        err = f"{type(e).__name__}: {e}"
    elapsed = (time.perf_counter() - t0) * 1000
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return r, elapsed, peak / 1024 / 1024, err


def collect_samples():
    """返回 [(name, binary_path, is_vuln)]."""
    samples = []
    for d in sorted(SAMPLE_DIR.iterdir()):
        if not d.is_dir() or not d.name.startswith("CVE_"):
            continue
        exe = d / f"vuln_{d.name}.exe"
        if exe.exists():
            samples.append((d.name, str(exe), VULN.get(d.name, False)))
    return samples


def main():
    ap = argparse.ArgumentParser(description="CVE堆溢出多工具对比")
    ap.add_argument("--output", "-o", default=str(ROOT / "cve_benchmark.csv"))
    ap.add_argument("--tools", "-t", nargs="*",
                    default=["binmind", "baseline", "angr", "ghidra", "qemu"])
    args = ap.parse_args()

    samples = collect_samples()
    print(f"[benchmark] {len(samples)} CVE samples, tools={args.tools}")

    tools = {
        "binmind": ("BinMind-DDSSC", lambda b: run_binmind(b, True)),
        "baseline": ("BinMind-Baseline", lambda b: run_binmind(b, False)),
        "angr": ("angr", run_angr),
        "ghidra": ("Ghidra", run_ghidra),
        "qemu": ("QEMU/Unicorn", run_qemu),
    }

    rows = []
    for name, path, is_vuln in samples:
        for t in args.tools:
            if t not in tools:
                continue
            label, fn = tools[t]
            r, elapsed, peak, err = measure(lambda: fn(path))
            count = r.get("count", r.get("findings", 0))
            v = verdict_of(is_vuln, count)
            rows.append({
                "tool": label, "sample": name,
                "truth": "vuln" if is_vuln else "safe",
                "verdict": v, "findings": count,
                "tp": 1 if v == "TP" else 0, "fp": 1 if v == "FP" else 0,
                "fn": 1 if v == "FN" else 0, "tn": 1 if v == "TN" else 0,
                "time_ms": round(elapsed, 2),
                "peak_mem_mb": round(peak, 2),
                "error": err or "",
            })
        print(f"  {name}: done")

    out = Path(args.output)
    with open(out, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"[csv] {out}")

    summary = {}
    for t in args.tools:
        if t not in tools:
            continue
        label, _ = tools[t]
        tr = [r for r in rows if r["tool"] == label]
        tp = sum(r["tp"] for r in tr)
        fp = sum(r["fp"] for r in tr)
        fn = sum(r["fn"] for r in tr)
        tn = sum(r["tn"] for r in tr)
        recall = tp / max(tp + fn, 1) * 100
        precision = tp / max(tp + fp, 1) * 100
        fpr = fp / max(fp + tn, 1) * 100
        f1 = 2 * tp / max(2 * tp + fp + fn, 1)
        summary[label] = {"TP": tp, "FP": fp, "FN": fn, "TN": tn,
                          "Recall": round(recall, 2),
                          "Precision": round(precision, 2),
                          "FPR": round(fpr, 2), "F1": round(f1, 4),
                          "avg_time_ms": round(
                              sum(r["time_ms"] for r in tr) / max(len(tr), 1), 2)}
    with open(ROOT / "cve_benchmark_summary.json", "w",
              encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    for label, s in summary.items():
        print(f"  {label}: {json.dumps(s)}")


if __name__ == "__main__":
    main()
