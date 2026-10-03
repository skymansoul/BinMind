#!/usr/bin/env python
# coding: utf-8
# tests/multi_fp_regression/run_multi.py — 多类型 (heap/uaf/fmt) 误报回归一键执行
# 对三个误报基准集 (heap_fp_benchmark / uaf_fp_benchmark / fmt_fp_benchmark)
# 编译 + 扫描 (各类型改进检测器 vs 基线) + 收集指标。
# 输出: results/ 下 per-type raw_scan.json + metrics.csv + summary.json
# 用法: python run_multi.py [--type heap|uaf|fmt|all]

import json
import re
import subprocess
import sys
import time
from pathlib import Path

_HERE = Path(__file__).parent
_INFO_DIR = _HERE.parent.parent
_ANALYSIS = _INFO_DIR / "analysis"
for _p in (str(_ANALYSIS), str(_INFO_DIR), str(_HERE)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from heap_overflow_v2 import detect_heap_overflow_v2                 # noqa
from fc_vra_detector import detect_heap_overflow_fcv3                # noqa
from uaf_detector_v2 import detect_uaf_v2                            # noqa
from uaf_fc_detector import detect_uaf_fcv3                          # noqa
from format_string_v3 import detect_format_string_v3                 # noqa
from fmt_fc_detector import detect_format_string_fcv3                # noqa

THRESHOLD = 0.25

TYPE_DIRS = {
    "heap": "heap_fp_benchmark",
    "uaf": "uaf_fp_benchmark",
    "fmt": "fmt_fp_benchmark",
}

ALLOC_RE = re.compile(r"\b(malloc|calloc|realloc)\s*\(")
WRITE_RE = re.compile(r"\b(memcpy|memmove|strcpy|strcat|strncpy|sprintf|"
                      r"snprintf|gets|read|fread|recv|scanf)\s*\(")


def _naive(code: str, vtype: str) -> dict:
    findings = []
    if vtype == "heap":
        a, w = len(ALLOC_RE.findall(code)), len(WRITE_RE.findall(code))
        if a and w:
            findings.append({"confidence": 0.9})
    elif vtype == "uaf":
        if re.search(r"\bfree\s*\(", code) and \
           re.search(r"->|\[[^]]*\]\s*=|&\s*\*", code):
            findings.append({"confidence": 0.9})
    elif vtype == "fmt":
        if re.search(r"\b(printf|fprintf|sprintf|snprintf|syslog|vprintf)"
                     r"\s*\(\s*[^\"(]", code):
            findings.append({"confidence": 0.9})
    return {"detected": bool(findings), "findings": findings}


def _detectors(vtype: str):
    if vtype == "heap":
        return {
            "NAIVE": lambda c: _naive(c, "heap"),
            "PSVR_HLM_v2": lambda c: _wrap(c, detect_heap_overflow_v2),
            "FC_VRA_v3": lambda c: _wrap(c, detect_heap_overflow_fcv3),
        }
    if vtype == "uaf":
        return {
            "NAIVE": lambda c: _naive(c, "uaf"),
            "UAF_v2": lambda c: _wrap_list(c, detect_uaf_v2),
            "UAF_FC_v3": lambda c: _wrap_list(c, detect_uaf_fcv3),
        }
    return {
        "NAIVE": lambda c: _naive(c, "fmt"),
        "FMT_v3": lambda c: _wrap_list(c, detect_format_string_v3),
        "FMT_FC_v3": lambda c: _wrap_list(c, detect_format_string_fcv3),
    }


def _wrap(code, fn) -> dict:
    t0 = time.time()
    r = fn(code=code, min_confidence=THRESHOLD)
    el = (time.time() - t0) * 1000
    return {"detected": r["stats"]["total"] > 0, "findings": r["findings"],
            "elapsed_ms": round(el, 1),
            "fp_reduction_pct": r.get("fp_reduction_pct", 0.0),
            "pairs": r.get("alloc_write_pairs_total", 0),
            "ablation": r.get("ablation", {})}


def _wrap_list(code, fn) -> dict:
    t0 = time.time()
    fs = [f for f in fn(code) if f.get("confidence", 0) >= THRESHOLD]
    el = (time.time() - t0) * 1000
    return {"detected": len(fs) > 0, "findings": fs,
            "elapsed_ms": round(el, 1)}


def _scan_type(vtype: str, samples_dir: Path, out: Path):
    results = {"threshold": THRESHOLD, "samples": {}}
    detectors = _detectors(vtype)
    for d in sorted(samples_dir.iterdir()):
        vuln = d / "vuln.c"
        if not vuln.exists():
            continue
        code = vuln.read_text(encoding="utf-8", errors="replace")
        truth = json.loads((d / "truth.json").read_text(encoding="utf-8"))
        tools = {}
        for name, fn in detectors.items():
            tools[name] = fn(code)
        results["samples"][d.name] = {
            "label": truth.get("label", "tn"),
            "expect_overflow": truth.get("expect_overflow", False),
            "tools": tools,
        }
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    return results


def _collect(vtype: str, raw: dict) -> list:
    rows = []
    for tool in ("NAIVE",):
        pass
    tools = set()
    for s in raw["samples"].values():
        tools.update(s["tools"].keys())
    for tool in sorted(tools):
        tp = fp = fn = tn = 0
        tsum = 0.0
        for sid, s in raw["samples"].items():
            r = s["tools"].get(tool, {})
            tsum += r.get("elapsed_ms", 0)
            if s["expect_overflow"]:
                if r.get("detected"):
                    tp += 1
                else:
                    fn += 1
            else:
                if r.get("detected"):
                    fp += 1
                else:
                    tn += 1
        n = tp + fn
        p = tp + fp
        rec = tp / n * 100 if n else 0
        fpr = fp / (fp + tn) * 100 if (fp + tn) else 0
        prec = tp / p * 100 if p else 0
        f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) else 0
        rows.append({"type": vtype, "tool": tool, "TP": tp, "FP": fp,
                     "FN": fn, "TN": tn, "recall_pct": round(rec, 1),
                     "fpr_pct": round(fpr, 1), "precision_pct": round(prec, 1),
                     "f1_pct": round(f1, 1),
                     "avg_time_ms": round(tsum / max(tp + fp + fn + tn, 1), 1)})
    return rows


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--type", default="all", choices=["all", "heap", "uaf", "fmt"])
    parser.add_argument("--compile", action="store_true",
                        help="先编译样本 (需要 gcc)")
    args = parser.parse_args()

    types = ["heap", "uaf", "fmt"] if args.type == "all" else [args.type]
    results_dir = _HERE / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    all_summary = []
    for vtype in types:
        samples_dir = _INFO_DIR / "tests" / TYPE_DIRS[vtype]
        if args.compile:
            for d in sorted(samples_dir.iterdir()):
                if (d / "vuln.c").exists():
                    subprocess.run(["gcc", "-Wall", "-Wextra", "-O0", "-g",
                                    "-o", str(d / "sample.exe"),
                                    str(d / "vuln.c")], capture_output=True)
        print(f"=== scan {vtype} ===")
        raw = _scan_type(vtype, samples_dir, results_dir / f"raw_scan_{vtype}.json")
        rows = _collect(vtype, raw)
        with open(results_dir / f"metrics_{vtype}.csv", "w", encoding="utf-8") as f:
            f.write("type,tool,TP,FP,FN,TN,recall_pct,fpr_pct,"
                    "precision_pct,f1_pct,avg_time_ms\n")
            for r in rows:
                f.write(f"{r['type']},{r['tool']},{r['TP']},{r['FP']},{r['FN']},"
                        f"{r['TN']},{r['recall_pct']},{r['fpr_pct']},"
                        f"{r['precision_pct']},{r['f1_pct']},"
                        f"{r['avg_time_ms']}\n")
        all_summary.extend(rows)
        print(f"  {vtype}: " + ", ".join(
            f"{r['tool']}={r['recall_pct']}%/{r['fpr_pct']}%" for r in rows))

    with open(results_dir / "summary_multi.json", "w", encoding="utf-8") as f:
        json.dump(all_summary, f, indent=2, ensure_ascii=False)
    print(f"\nsummary: {results_dir / 'summary_multi.json'}")


if __name__ == "__main__":
    main()
