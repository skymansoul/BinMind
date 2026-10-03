#!/usr/bin/env python
# coding: utf-8
# eval/validate_real_cve.py — 真实 CVE 语料验证
# 在仓库既有的 tests/regression/samples (104 个 CVE 复现样本) 上,
# 对三个堆溢出检测器 (NAIVE / PSVR_HLM_v2 / FC_VRA_v3) 实测:
#   召回: 真实堆溢出 CVE 样本是否被检出
#   跨类型误报: uaf/fmt/int/stack 等非堆样本是否被误报为 heap-overflow
# 这是"公开样本"锚点的核心数据: 不依赖合成样本, 直接用 CVE 编号语料。
# 输出: eval/real_cve_validation.csv + real_cve_validation.json + 摘要
# 用法: python eval/validate_real_cve.py

import csv
import json
import re
import sys
import time
from pathlib import Path

_EVAL = Path(__file__).parent
_INFO = _EVAL.parent
_SAMPLES = _INFO / "tests" / "regression" / "samples"
for _p in (str(_INFO / "analysis"), str(_INFO)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from heap_overflow_v2 import detect_heap_overflow_v2      # noqa
from fc_vra_detector import detect_heap_overflow_fcv3     # noqa

THRESHOLD = 0.25

# 真实堆溢出 CVE 样本判定 (来自既有基准的 ground truth + 目录名)
HO_KEYWORDS = ("heartbleed", "_ghost", "ghost", "heap_overflow", "_heap",
               "libssh_heap", "proftpd_heap", "grub_heap", "sudo_heap",
               "kernel_heap", "linux_heap", "malloc_memcpy", "strcpy_heap",
               "off_by_one_heap", "loop_heap_overflow", "int_overflow_malloc",
               "realloc_misuse", "calloc_read_overflow", "heap")


def is_ho(name: str) -> bool:
    low = name.lower()
    return any(k in low for k in HO_KEYWORDS)


def run_naive(code: str) -> dict:
    allocs = re.findall(r"\b(malloc|calloc|realloc)\s*\(", code)
    writes = re.findall(
        r"\b(memcpy|memmove|strcpy|strcat|strncpy|sprintf|snprintf|"
        r"gets|read|fread|recv)\s*\(", code)
    has_input = bool(re.search(r"\b(recv|read|fread|scanf|gets|fgets)\s*\(",
                               code))
    if allocs and writes:
        return {"detected": True,
                "findings": [{"confidence": 0.95 if has_input else 0.85}]}
    return {"detected": False, "findings": []}


def main():
    rows = []
    for d in sorted(_SAMPLES.iterdir()):
        vuln = d / "vuln.c"
        if not vuln.exists():
            continue
        code = vuln.read_text(encoding="utf-8", errors="replace")
        gt_ho = is_ho(d.name)

        t0 = time.time()
        naive = run_naive(code)
        t1 = time.time()
        v2 = detect_heap_overflow_v2(code=code, min_confidence=THRESHOLD)
        t2 = time.time()
        v3 = detect_heap_overflow_fcv3(code=code, min_confidence=THRESHOLD)
        t3 = time.time()

        rows.append({
            "sample": d.name, "is_heap_overflow": gt_ho,
            "NAIVE": int(naive["detected"]),
            "PSVR_HLM_v2": int(v2["stats"]["total"] > 0),
            "FC_VRA_v3": int(v3["stats"]["total"] > 0),
            "v2_findings": v2["stats"]["total"],
            "v3_findings": v3["stats"]["total"],
            "v2_ms": round((t2 - t1) * 1000, 1),
            "v3_ms": round((t3 - t2) * 1000, 1),
        })

    # 汇总
    ho = [r for r in rows if r["is_heap_overflow"]]
    non_ho = [r for r in rows if not r["is_heap_overflow"]]
    summary = {}
    for tool in ("NAIVE", "PSVR_HLM_v2", "FC_VRA_v3"):
        rec = sum(1 for r in ho if r[tool]) / max(len(ho), 1) * 100
        fp = sum(1 for r in non_ho if r[tool]) / max(len(non_ho), 1) * 100
        fp_abs = sum(1 for r in non_ho if r[tool])
        summary[tool] = {"recall_pct": round(rec, 1),
                         "cross_type_fpr_pct": round(fp, 1),
                         "cross_type_fp_abs": fp_abs,
                         "ho_samples": len(ho),
                         "non_ho_samples": len(non_ho)}

    out_csv = _EVAL / "real_cve_validation.csv"
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["sample", "is_heap_overflow", "NAIVE", "PSVR_HLM_v2",
                    "FC_VRA_v3", "v2_findings", "v3_findings",
                    "v2_ms", "v3_ms"])
        for r in rows:
            w.writerow([r["sample"], int(r["is_heap_overflow"]), r["NAIVE"],
                        r["PSVR_HLM_v2"], r["FC_VRA_v3"], r["v2_findings"],
                        r["v3_findings"], r["v2_ms"], r["v3_ms"]])
    out_json = _EVAL / "real_cve_validation.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump({"summary": summary, "rows": rows}, f, indent=2,
                  ensure_ascii=False)

    print(f"\n真实 CVE 语料: {len(rows)} 样本 "
          f"(堆溢出 {len(ho)} / 其他类型 {len(non_ho)})")
    print(f"{'Tool':<14} {'堆溢出召回':>10} {'跨类型误报率':>12} {'误报绝对数':>10}")
    print("-" * 50)
    for tool in ("NAIVE", "PSVR_HLM_v2", "FC_VRA_v3"):
        s = summary[tool]
        print(f"{tool:<14} {s['recall_pct']:>9.1f}% {s['cross_type_fpr_pct']:>11.1f}% "
              f"{s['cross_type_fp_abs']:>10}")
    print(f"\nCSV:  {out_csv}")
    print(f"JSON: {out_json}")


if __name__ == "__main__":
    main()
