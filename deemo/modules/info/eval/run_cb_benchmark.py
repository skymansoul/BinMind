#!/usr/bin/env python
"""eval/run_cb_benchmark.py — CB-HOD v1.0 vs AC3 Baseline 对比基准
对 heap overflow 样本分别运行 3 种方法:
  1. AC3-v1 (导入表配对, 无过滤)
  2. PSVR-HLM-v3.0 (当前管线: P0→P0.5→P1→P2→P3→P4)
  3. CB-HOD-v1.0 (约束驱动: PtrTrack→Constraint→HLM)
输出: CSV + JSON + 终端汇总"""
import os, sys, json, time, csv
from pathlib import Path
from datetime import datetime

_PROJ = Path(__file__).parent.parent
_ANA = _PROJ / "analysis"
_TESTS = _PROJ / "tests" / "regression"
for p in (str(_ANA), str(_PROJ)):
    if p not in sys.path: sys.path.insert(0, p)

SAMPLES_DIR = _TESTS / "samples"
GT_FILE = _TESTS / "ground_truth.json"
OUT_DIR = Path(__file__).parent


def load_gt():
    if GT_FILE.exists():
        with open(GT_FILE) as f:
            return json.load(f).get("samples", {})
    return {}


def classify(name: str) -> str:
    """判断样本是否为 heap overflow 正/负样本。复用 run_unified_test 逻辑。"""
    n = name.lower()
    if name.startswith("NEG-"):
        if any(k in n for k in ("heap","malloc","calloc","realloc","memcpy",
                                  "overflow","alloc","sizeof","fortify","guard")):
            return "negative"
        return None
    if name.startswith("CVE-"):
        # 明确包含 heap 关键词的
        if "heap" in n:
            return "positive"
        # heartbleed / ghost 是堆漏洞
        if "heartbleed" in n or "ghost" in n:
            return "positive"
        # malloc/realloc/calloc + overflow 模式
        if "malloc_memcpy" in n or "realloc_misuse" in n:
            return "positive"
        if "strcpy_heap" in n or "calloc_read" in n:
            return "positive"
        if "off_by_one" in n or "loop_heap" in n:
            return "positive"
        # 特定 CVE: libssh/proftpd/grub/sudo/kernel heap
        for tag in ("libssh_heap", "proftpd_heap", "grub_heap", "sudo_heap",
                     "kernel_heap", "linux_heap", "int_overflow_malloc"):
            if tag in n:
                return "positive"
    return None


def run_baseline(code: str, sample_name: str) -> dict:
    """AC3 v1 baseline: pure import pairing, no filtering."""
    t0 = time.time()
    from heap_overflow_v2 import _make_pairs_from_code
    pairs = _make_pairs_from_code(code, {})
    elapsed = round((time.time() - t0) * 1000, 1)
    findings = [p for p in pairs if p["overflow_risk"] >= 0.25]
    return {"tool": "AC3-v1-Baseline", "pairs_total": len(pairs),
            "findings": len(findings), "elapsed_ms": elapsed}


def run_psvr_hlm(code: str, imports: dict, checksec: dict) -> dict:
    """PSVR-HLM v3.0: the full existing pipeline."""
    t0 = time.time()
    from heap_overflow_v2 import detect_heap_overflow_v2
    result = detect_heap_overflow_v2(code=code, imports=imports,
                                      checksec=checksec)
    elapsed = round((time.time() - t0) * 1000, 1)
    stats = result.get("stats", {})
    return {"tool": "PSVR-HLM-v3.0", "pairs_total": result.get("alloc_write_pairs_total", 0),
            "findings": stats.get("total", 0),
            "vra_filtered": result.get("vra_stats", {}).get("definitely_safe", 0),
            "fp_reduction_pct": result.get("fp_reduction_pct", 0),
            "elapsed_ms": elapsed}


def run_cb_hod(code: str, arch: str = "x86_64") -> dict:
    """CB-HOD v1.0: constraint-driven, pointer-tracking based."""
    t0 = time.time()
    from heap_fp_filter import analyze_heap_safety
    result = analyze_heap_safety(code, arch=arch)
    elapsed = round((time.time() - t0) * 1000, 1)
    stats = result.get("stats", {})
    return {"tool": "CB-HOD-v1.0",
            "pairs_total": stats.get("total_bindings", 0),
            "findings": stats.get("reported", 0),
            "proven_safe": stats.get("proven_safe", 0),
            "fp_reduction_pct": stats.get("fp_reduction_vs_pair_based", 0),
            "elapsed_ms": elapsed}


def main():
    gt = load_gt()
    heap_dirs = []
    for d in sorted(SAMPLES_DIR.iterdir()):
        if not d.is_dir() or d.name == "tests":
            continue
        c = classify(d.name)
        if c in ("positive", "negative"):
            heap_dirs.append((d, c))

    print(f"{'='*70}")
    print(f"CB-HOD BENCHMARK: {len(heap_dirs)} heap overflow samples")
    print(f"{'='*70}")

    all_results = []
    tool_stats = {}

    for d, sample_type in heap_dirs:
        src = d / "vuln.c"
        if not src.exists():
            continue
        code = src.read_text(encoding="utf-8", errors="replace")

        sample_gt = gt.get(d.name, {})
        is_vuln = sample_gt.get("is_vulnerable", sample_type == "positive")

        runners = [
            run_baseline(code, d.name),
            run_psvr_hlm(code, {}, {"arch": "x86_64"}),
            run_cb_hod(code),
        ]

        for r in runners:
            r["sample"] = d.name
            r["sample_type"] = sample_type
            r["is_vulnerable"] = is_vuln
            detected = r["findings"] > 0

            if is_vuln:
                r["status"] = "TP" if detected else "FN"
            else:
                r["status"] = "FP" if detected else "TN"

            all_results.append(r)
            tn = r["tool"]
            if tn not in tool_stats:
                tool_stats[tn] = {"TP":0,"FP":0,"TN":0,"FN":0,"total_ms":0,"count":0}
            st = tool_stats[tn]
            if r["status"] in st: st[r["status"]] += 1
            st["total_ms"] += r.get("elapsed_ms", 0)
            st["count"] += 1

            tag = f"[{r['status']}]"
            print(f"  {tag} {tn:20s} {d.name:40s} f={r['findings']:2d} {r.get('elapsed_ms',0):6.1f}ms")

    # Summary
    print(f"\n{'='*70}")
    print(f"COMPARISON SUMMARY")
    print(f"{'='*70}")
    print(f"{'Tool':<22s} {'Samples':>7s} {'TP':>4s} {'FP':>4s} {'TN':>4s} {'FN':>4s}  "
          f"{'Recall':>7s} {'Prec':>7s} {'FPR':>7s} {'F1':>7s} {'Time':>8s}")
    print(f"{'-'*70}")

    summary_rows = []
    for tool in ["AC3-v1-Baseline", "PSVR-HLM-v3.0", "CB-HOD-v1.0"]:
        st = tool_stats.get(tool, {})
        if not st: continue
        tp, fp, tn, fn = st["TP"], st["FP"], st["TN"], st["FN"]
        rec = tp / max(tp + fn, 1)
        prec = tp / max(tp + fp, 1)
        fpr = fp / max(fp + tn, 1)
        f1_val = 2 * prec * rec / max(prec + rec, 0.01)
        avg_t = st["total_ms"] / max(st["count"], 1)
        print(f"{tool:<22s} {st['count']:>7d} {tp:>4d} {fp:>4d} {tn:>4d} {fn:>4d}  "
              f"{rec*100:>6.1f}% {prec*100:>6.1f}% {fpr*100:>6.1f}% {f1_val:>7.3f} {avg_t:>7.1f}ms")
        summary_rows.append({
            "Tool": tool, "Samples": st["count"],
            "TP": tp, "FP": fp, "TN": tn, "FN": fn,
            "Recall_pct": round(rec * 100, 1),
            "Precision_pct": round(prec * 100, 1),
            "FP_Rate_pct": round(fpr * 100, 1),
            "F1_Score": round(f1_val, 3),
            "Avg_Time_ms": round(avg_t, 1),
        })

    # Export
    csv_path = OUT_DIR / "cb_hod_benchmark.csv"
    with open(csv_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=summary_rows[0].keys())
        w.writeheader(); w.writerows(summary_rows)

    json_path = OUT_DIR / "cb_hod_benchmark.json"
    with open(json_path, "w") as f:
        json.dump({"summary": summary_rows, "details": all_results,
                   "timestamp": datetime.now().isoformat()},
                  f, indent=2, ensure_ascii=False, default=str)

    print(f"\nCSV: {csv_path}  JSON: {json_path}")
    return summary_rows


if __name__ == "__main__":
    main()
