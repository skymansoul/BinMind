#!/usr/bin/env python
# coding: utf-8
# tests/heap_fp_regression/scan_scheduler.py — 扫描调度模块
# 对 heap_fp_benchmark 全部样本运行三类内部检测器 (源码级):
#   AC3_source   — 导入表配对基线 (naive, 笛卡尔积)
#   PSVR_HLM_v2  — 值域+对齐+路径可行性基线
#   FC_VRA_v3    — 流相关值域分析
# 统一输出原始 JSON: {sample: {tool: {detected, findings, elapsed_ms,
#                                       fp_reduction_pct, ablation}}}
# 用法: python scan_scheduler.py [--threshold 0.25] [--out 结果JSON]

import json
import re
import sys
import time
from pathlib import Path

_ANALYSIS_DIR = Path(__file__).parent.parent.parent / "analysis"
for _p in (str(_ANALYSIS_DIR), str(_ANALYSIS_DIR.parent)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from heap_overflow_v2 import detect_heap_overflow_v2          # noqa: E402
from fc_vra_detector import detect_heap_overflow_fcv3         # noqa: E402

_SAMPLES_DIR = Path(__file__).parent.parent / "heap_fp_benchmark"
_DEFAULT_OUT = Path(__file__).parent / "results" / "raw_scan.json"

_ALLOC_WRITE_FUNCS = [
    "malloc", "calloc", "realloc", "memcpy", "memmove", "strcpy", "strcat",
    "strncpy", "strncat", "sprintf", "snprintf", "vsprintf", "read", "fread",
    "recv", "gets", "scanf", "fgets",
]


def _imports_from_code(code: str) -> dict:
    """从源码合成导入表 (模拟二进制导入). 供 AC3 基线使用。"""
    found = [f for f in _ALLOC_WRITE_FUNCS
             if re.search(rf"\b{f}\s*\(", code)]
    return {"all_imports": {"sim_binary": found}}


def run_ac3_source(code: str, threshold: float) -> dict:
    from info_collection.src.heap_overflow_detector import detect_heap_overflow
    imports = _imports_from_code(code)
    t0 = time.time()
    r = detect_heap_overflow(imports, strings=[], checksec={},
                             min_confidence=threshold)
    elapsed = (time.time() - t0) * 1000
    return {"detected": r["stats"]["total"] > 0,
            "findings": r["findings"], "stats": r["stats"],
            "elapsed_ms": round(elapsed, 1),
            "fp_reduction_pct": r.get("fp_reduction_pct", 0.0),
            "method": r.get("method", "AC3")}


def run_v2(code: str, threshold: float) -> dict:
    t0 = time.time()
    r = detect_heap_overflow_v2(code=code, min_confidence=threshold)
    elapsed = (time.time() - t0) * 1000
    return {"detected": r["stats"]["total"] > 0,
            "findings": r["findings"], "stats": r["stats"],
            "elapsed_ms": round(elapsed, 1),
            "fp_reduction_pct": r.get("fp_reduction_pct", 0.0),
            "pairs": r.get("alloc_write_pairs_total", 0),
            "method": r.get("method", "PSVR-HLM-v2")}


def run_fcv3(code: str, threshold: float) -> dict:
    t0 = time.time()
    r = detect_heap_overflow_fcv3(code=code, min_confidence=threshold)
    elapsed = (time.time() - t0) * 1000
    return {"detected": r["stats"]["total"] > 0,
            "findings": r["findings"], "stats": r["stats"],
            "elapsed_ms": round(elapsed, 1),
            "fp_reduction_pct": r.get("fp_reduction_pct", 0.0),
            "pairs": r.get("alloc_write_pairs_total", 0),
            "ablation": r.get("ablation", {}),
            "method": r.get("method", "FC-VRA-v3")}


def run_naive(code: str, threshold: float) -> dict:
    """NAIVE 基线: 无任何过滤的原始配对 — 代表"改进前"的高误报状态。
    只要源码中同时出现分配函数与写入函数即报, 置信度固定高值。"""
    t0 = time.time()
    allocs = re.findall(r"\b(malloc|calloc|realloc)\s*\(", code)
    writes = re.findall(
        r"\b(memcpy|memmove|strcpy|strcat|strncpy|sprintf|snprintf|"
        r"gets|read|fread|recv)\s*\(", code)
    pairs = len(allocs) * len(writes)
    has_input = bool(re.search(r"\b(recv|read|fread|scanf|gets|fgets)\s*\(", code))
    findings = []
    if allocs and writes:
        findings.append({
            "type": "heap-overflow", "alloc_func": "ANY", "write_func": "ANY",
            "confidence": 0.95 if has_input else 0.85,
            "severity": "High", "reason": "naive:alloc+write coexist",
        })
    elapsed = (time.time() - t0) * 1000
    return {"detected": len(findings) > 0, "findings": findings,
            "elapsed_ms": round(elapsed, 1), "pairs": pairs,
            "fp_reduction_pct": 0.0, "method": "NAIVE"}


def run_all(code: str, threshold: float) -> dict:
    return {
        "NAIVE": run_naive(code, threshold),
        "AC3_source": run_ac3_source(code, threshold),
        "PSVR_HLM_v2": run_v2(code, threshold),
        "FC_VRA_v3": run_fcv3(code, threshold),
    }


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", default=str(_SAMPLES_DIR))
    parser.add_argument("--out", default=str(_DEFAULT_OUT))
    parser.add_argument("--threshold", type=float, default=0.25)
    args = parser.parse_args()

    samples_dir = Path(args.samples)
    results = {"threshold": args.threshold, "samples": {}}

    for d in sorted(samples_dir.iterdir()):
        if not d.is_dir():
            continue
        vuln = d / "vuln.c"
        if not vuln.exists():
            continue
        code = vuln.read_text(encoding="utf-8", errors="replace")
        truth = {}
        tf = d / "truth.json"
        if tf.exists():
            truth = json.loads(tf.read_text(encoding="utf-8"))
        results["samples"][d.name] = {
            "label": truth.get("label", "unknown"),
            "expect_overflow": truth.get("expect_overflow", False),
            "tools": run_all(code, args.threshold),
        }
        print(f"  scanned {d.name}")

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"raw results: {args.out}")


if __name__ == "__main__":
    main()
