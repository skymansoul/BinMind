#!/usr/bin/env python
# coding: utf-8
# eval/run_benchmark_v2.py — 统一堆溢出检测基准 (FC-VRA 系列 vs 通用工具)
# 覆盖工具:
#   内部 (源码级):  NAIVE / AC3_source / PSVR_HLM_v2 / FC_VRA_v3
#   外部 (二进制级): Angr (CFGFast+危险符号) / Ghidra (无头) / QEMU (动态GT)
# 每个样本在两个变体上评估: 未加壳 (unpacked) 与 加壳仿真 (packed)。
# 加壳仿真的意义: 通用工具依赖导入表, 加壳后导入不可见 → 召回骤降;
# 我们的源码级 FC-VRA 不受加壳影响。
#
# 输出统一 CSV: tool,sample_id,group,detected,findings,fp_count,fn_count,
#               elapsed_s,peak_memory_mb
# 用法: python eval/run_benchmark_v2.py [--threshold 0.25]

import csv
import json
import os
import subprocess
import sys
import time
from pathlib import Path

_EVAL_DIR = Path(__file__).parent
_INFO_DIR = _EVAL_DIR.parent
_SAMPLES_DIR = _INFO_DIR / "tests" / "heap_fp_benchmark"
_BUILD_DIR = _INFO_DIR / "tests" / "heap_fp_regression" / "build"
_PACKED_DIR = _INFO_DIR / "tests" / "heap_fp_regression" / "build_packed"
_REGRESSION = _INFO_DIR / "tests" / "heap_fp_regression"

for _p in (str(_INFO_DIR / "analysis"), str(_INFO_DIR),
           str(_REGRESSION), str(_EVAL_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)


def _peak_mem() -> float:
    try:
        import psutil
        return psutil.Process().memory_info().rss / 1024 / 1024
    except Exception:
        return 0.0


# 内部工具 (源码级)
def _internal_run(code: str, threshold: float):
    from scan_scheduler import run_all
    return run_all(code, threshold)


# 外部工具 (二进制级)
def run_angr(target: str, timeout: int = 180) -> dict:
    t0 = time.time()
    try:
        import angr
        p = angr.Project(str(target), auto_load_libs=False)
        dang = {"memcpy", "strcpy", "sprintf", "strncpy", "gets",
                "malloc", "calloc", "realloc", "read", "recv", "scanf",
                "memmove", "strcat", "fread", "fgets", "snprintf"}
        # 优先从导入表解析符号名 (MinGW PE 下 CFGFast 不解析函数名)
        import_names = set()
        mo = p.loader.main_object
        for k in mo.imports.keys():
            import_names.add(str(k).lower().rstrip('aw'))
        found = sorted(import_names & dang)
        # 补充: CFG 中可解析的危险函数名
        cfg = p.analyses.CFGFast()
        for f in cfg.functions:
            if f in dang and f not in found:
                found.append(f)
        elapsed = round(time.time() - t0, 3)
        return {"tool": "Angr", "detected": len(found) > 0,
                "findings_count": len(found), "elapsed_s": elapsed,
                "detail": found}
    except Exception as e:
        return {"tool": "Angr", "detected": False, "findings_count": 0,
                "elapsed_s": round(time.time() - t0, 3), "error": str(e)[:80]}


def run_ghidra(target: str) -> dict:
    from ghidra_headless import analyze
    t0 = time.time()
    r = analyze(str(target))
    elapsed = round(time.time() - t0, 3)
    if r.get("error"):
        return {"tool": "Ghidra", "detected": False, "findings_count": 0,
                "elapsed_s": elapsed, "error": r["error"], "skip": True}
    found = r.get("found", 0)
    return {"tool": "Ghidra", "detected": found > 0, "findings_count": found,
            "elapsed_s": elapsed}


def run_qemu(target: str) -> dict:
    from qemu_tracer import trace_execution
    t0 = time.time()
    r = trace_execution(str(target), timeout=25)
    elapsed = round(time.time() - t0, 3)
    if r.get("error"):
        return {"tool": "QEMU", "detected": False, "findings_count": 0,
                "elapsed_s": elapsed, "error": r["error"], "skip": True}
    if str(target).endswith(".exe") or str(target).endswith(".dll"):
        return {"tool": "QEMU", "detected": False, "findings_count": 0,
                "elapsed_s": elapsed, "skip": True,
                "error": "PE binary not runnable under qemu-user"}
    return {"tool": "QEMU", "detected": r.get("dangerous_calls_detected", 0) > 0,
            "findings_count": r.get("dangerous_calls_detected", 0),
            "elapsed_s": elapsed}


# 主流程
def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--threshold", type=float, default=0.25)
    args = parser.parse_args()

    rows = []
    results = {"threshold": args.threshold, "samples": {}}

    samples = sorted(d for d in _SAMPLES_DIR.iterdir()
                     if d.is_dir() and (d / "vuln.c").exists())

    for d in samples:
        sid = d.name
        code = (d / "vuln.c").read_text(encoding="utf-8", errors="replace")
        truth = json.loads((d / "truth.json").read_text(encoding="utf-8"))
        expect = truth.get("expect_overflow", False)
        label = truth.get("label", "tn")

        unpacked = _BUILD_DIR / sid / "sample.exe"
        packed = _PACKED_DIR / sid / "sample_packed.exe"
        bin_unpacked = str(unpacked) if unpacked.exists() else ""
        bin_packed = str(packed) if packed.exists() else ""

        results["samples"][sid] = {"label": label, "expect": expect,
                                   "tools": {}}

        # 内部工具 (源码级, 与加壳无关)
        mem0 = _peak_mem()
        internal = _internal_run(code, args.threshold)
        mem_int = _peak_mem() - mem0
        for tool, res in internal.items():
            rows.append({
                "tool": tool, "sample_id": sid, "group": "unpacked",
                "detected": int(res["detected"]),
                "findings": res["stats"].get("total", 0) if "stats" in res
                            else len(res.get("findings", [])),
                "fp_count": 0, "fn_count": int(not res["detected"] and expect),
                "elapsed_s": round(res.get("elapsed_ms", 0) / 1000, 3),
                "peak_memory_mb": round(max(mem_int, 0), 1),
                "skip": 0,
            })
            results["samples"][sid]["tools"].setdefault(tool, {})["source"] = res

        # 外部工具 (二进制级, 未加壳 + 加壳)
        for gname, bpath in (("unpacked", bin_unpacked),
                             ("packed", bin_packed)):
            if not bpath:
                continue
            for fn in (run_angr, run_ghidra, run_qemu):
                mem0 = _peak_mem()
                r = fn(bpath)
                mem_ext = _peak_mem() - mem0
                rows.append({
                    "tool": r["tool"], "sample_id": sid, "group": gname,
                    "detected": int(r["detected"]),
                    "findings": r.get("findings_count", 0),
                    "fp_count": 0,
                    "fn_count": int(not r["detected"] and expect),
                    "elapsed_s": r.get("elapsed_s", 0),
                    "peak_memory_mb": round(max(mem_ext, 0), 1),
                    "skip": int(r.get("skip", False)),
                })
                results["samples"][sid]["tools"].setdefault(
                    r["tool"], {})[gname] = r

        print(f"  bench {sid} ({label}, expect={expect})")

    out_csv = _EVAL_DIR / "benchmark_v2.csv"
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["tool", "sample_id", "group", "detected", "findings",
                    "fp_count", "fn_count", "elapsed_s", "peak_memory_mb",
                    "skip"])
        for r in rows:
            w.writerow([r["tool"], r["sample_id"], r["group"], r["detected"],
                        r["findings"], r["fp_count"], r["fn_count"],
                        r["elapsed_s"], r["peak_memory_mb"], r["skip"]])

    out_json = _EVAL_DIR / "benchmark_v2.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print(f"\nCSV:  {out_csv}")
    print(f"JSON: {out_json}")


if __name__ == "__main__":
    main()
