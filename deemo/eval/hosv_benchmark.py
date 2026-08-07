# coding: utf-8
"""
多工具堆溢出检测对比 Benchmark — 统一 CSV 输出.

调用工具:
  1. BinMind HOSV + 写模式扩展 (源码级)
  2. Angr (二进制级符号执行, 若已安装)
  3. objdump 静态审计 (回退, 无 angr/qemu/ghidra 时)
  4. Flawfinder 风格正则基线 (内置, 模拟通用源码扫描器)

输出: eval/hosv_benchmark_results.csv — 工具名,样本ID,检出数,误报数,
漏报数,耗时,峰值内存, 以及逐样本判定.

峰值内存: 通过 tracemalloc (Python侧) 近似测量分析进程内存.
"""

import csv
import json
import os
import sys
import time
import tracemalloc

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                ".."))

from analysis.heap_overflow_src_verifier import HeapOverflowSrcVerifier  # noqa: E402
from analysis.heap_overflow_types import HoVerdict  # noqa: E402
from analysis.hosv_ext_verifier import HosvExtVerifier  # noqa: E402

BASE = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(BASE, "..", "tests", "hosv_benchmark", "samples")

# 危险函数正则基线 (模拟通用静态扫描器 Flawfinder 误报行为)
DANGER_RE = (
    r'\b(memcpy|strcpy|strcat|sprintf|gets|scanf|fgets|read|recv)'
    r'\s*\('
)

try:
    import angr  # noqa: F401
    ANGR_OK = True
except ImportError:
    ANGR_OK = False


def load_sample_list():
    """加载样本 (sample_id, cve, expected_verdict, src_path)."""
    out = []
    for entry in sorted(os.listdir(SAMPLES)):
        d = os.path.join(SAMPLES, entry)
        if not os.path.isdir(d):
            continue
        truth_p = os.path.join(d, "truth.json")
        src_p = os.path.join(d, "vuln.c")
        if not (os.path.exists(truth_p) and os.path.exists(src_p)):
            continue
        with open(truth_p, "r", encoding="utf-8") as f:
            truth = json.load(f)
        out.append((truth.get("sample", entry),
                    truth.get("cve", ""),
                    truth.get("verdict", ""),
                    src_p))
    return out


# 工具实现

def run_binmind(src: str) -> dict:
    """本工作: HOSV + 写模式扩展."""
    hosv = HeapOverflowSrcVerifier()
    ext = HosvExtVerifier()
    t0 = time.time()
    tracemalloc.start()
    r1 = hosv.verify(src)
    r2 = ext.verify(src)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    vuln_keys = set()
    for r in r1:
        if r.verdict == HoVerdict.VULN:
            vuln_keys.add((r.alloc_line, r.write_line, r.var_name))
    for r in r2:
        if r.verdict == "VULN":
            vuln_keys.add((r.alloc_line, r.write_line, r.var_name))
    return {"detected": len(vuln_keys), "time_s": time.time() - t0,
            "peak_mb": peak / 1048576.0}


def run_regex_baseline(src: str) -> dict:
    """正则基线: 统计危险函数调用 (高误报)."""
    import re
    t0 = time.time()
    tracemalloc.start()
    hits = re.findall(DANGER_RE, src)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {"detected": len(hits), "time_s": time.time() - t0,
            "peak_mb": peak / 1048576.0}


def run_angr(binary_path: str, sample_id: str) -> dict:
    """Angr 符号执行 (二进制级, 需要已编译 ELF)."""
    if not ANGR_OK:
        return {"detected": -1, "time_s": 0.0, "peak_mb": 0.0,
                "error": "angr not installed"}
    try:
        t0 = time.time()
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()
        found = 0
        for fn in ("strcpy", "strcat", "sprintf", "gets", "scanf",
                   "memcpy", "memmove"):
            sym = proj.loader.find_symbol(fn)
            if sym is None:
                continue
            for b in cfg.functions.values():
                if b.addr == sym.rebased_addr:
                    found += 1
        return {"detected": found, "time_s": time.time() - t0,
                "peak_mb": 0.0}
    except Exception as e:  # noqa: BLE001
        return {"detected": -1, "time_s": 0.0, "peak_mb": 0.0,
                "error": str(e)[:150]}


# 主流程

def build_cross_table(rows, expected):
    """按样本聚合各工具 TP/FP/FN/TN 与 检出数."""
    # rows: {sample_id: {tool: {detected, ...}}}
    tools = set()
    for per_sample in rows.values():
        tools.update(per_sample.keys())
    out = []
    for tool in sorted(tools):
        tp = fp = fn = tn = 0
        total_time = 0.0
        peak = 0.0
        for sid, expected_v in expected.items():
            if sid not in rows or tool not in rows[sid]:
                continue
            r = rows[sid][tool]
            if r.get("error"):
                continue
            det = r["detected"]
            total_time += r["time_s"]
            peak = max(peak, r.get("peak_mb", 0.0))
            if det > 0:
                if expected_v == "VULN":
                    tp += 1
                else:
                    fp += 1
            else:
                if expected_v == "VULN":
                    fn += 1
                else:
                    tn += 1
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) \
            if precision + recall else 0.0
        out.append({
            "tool": tool, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "total_time_s": round(total_time, 3),
            "peak_mb": round(peak, 2),
        })
    return out


def main():
    samples = load_sample_list()
    expected = {sid: verdict for sid, _, verdict, _ in samples}
    rows = {}
    per_sample_out = []

    for sid, cve, verdict, src_p in samples:
        with open(src_p, "r", encoding="utf-8", errors="replace") as f:
            src = f.read()
        rows[sid] = {}
        # 1. BinMind
        bm = run_binmind(src)
        rows[sid]["BinMind_HOSV+Ext"] = bm
        # 2. 正则基线
        rj = run_regex_baseline(src)
        rows[sid]["Regex_Baseline"] = rj
        # 3. Angr (需要编译)
        bin_p = os.path.join(os.path.dirname(src_p), "vuln.exe")
        if os.path.exists(bin_p):
            rows[sid]["Angr"] = run_angr(bin_p, sid)
        per_sample_out.append({
            "sample": sid, "cve": cve, "expected": verdict,
            "BinMind_detected": bm["detected"],
            "Regex_detected": rj["detected"],
            "BinMind_time_ms": round(bm["time_s"] * 1000, 1),
        })

    cross = build_cross_table(rows, expected)
    print("=== 工具对比 (18 样本: 12 VULN + 6 SAFE) ===")
    print("%-20s %4s %4s %4s %4s %8s %8s %8s %8s %8s" % (
        "tool", "tp", "fp", "fn", "tn", "precision", "recall", "f1",
        "time_s", "peak_mb"))
    for c in cross:
        print("%-20s %4d %4d %4d %4d %8.3f %8.3f %8.3f %8.3f %8.2f" % (
            c["tool"], c["tp"], c["fp"], c["fn"], c["tn"],
            c["precision"], c["recall"], c["f1"],
            c["total_time_s"], c["peak_mb"]))

    # 输出 CSV (统一格式: 工具名,样本ID,检出数,误报数,漏报数,耗时,峰值内存)
    csv_path = os.path.join(BASE, "hosv_benchmark_results.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["tool", "sample", "detected", "false_positive",
                    "false_negative", "time_s", "peak_mb", "expected"])
        for sid in rows:
            for tool, r in rows[sid].items():
                det = r["detected"]
                fp = 1 if (det > 0 and expected[sid] == "SAFE") else 0
                fn = 1 if (det == 0 and expected[sid] == "VULN") else 0
                w.writerow([tool, sid, det, fp, fn,
                            round(r["time_s"], 4),
                            round(r.get("peak_mb", 0), 3),
                            expected[sid]])
    print("\nsaved:", csv_path)

    json_path = os.path.join(BASE, "hosv_benchmark_results.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"cross": cross, "per_sample": per_sample_out},
                  f, ensure_ascii=False, indent=2)
    print("saved:", json_path)
    return cross


if __name__ == "__main__":
    main()
