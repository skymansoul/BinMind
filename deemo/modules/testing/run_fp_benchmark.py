"""一键误报率基准 — 编译 → 扫描 (absint baseline vs giva) → 标签对比.

用法: python run_fp_benchmark.py
输出:
  - fp_benchmark_results.json: 每样本检出状态 + 汇总指标
  - fp_benchmark_results.csv:  每样本一行 (样本, 类别, 期望, baseline, giva, 状态)
  - 终端: 每样本状态表 + FP/FN 降幅统计

样本集: heap_samples/ (25 漏洞) + heap_benign_samples/ (16 良性)
ground truth: sample_labels.json
"""

import argparse
import json
import os
import subprocess
import sys
import time

BASE = os.path.dirname(os.path.abspath(__file__))
PROJ_ROOT = os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))
if PROJ_ROOT not in sys.path:
    sys.path.insert(0, PROJ_ROOT)

from modules.analysis.static.heap_analysis.giva_detector import GivaScanner  # noqa: E402
from modules.analysis.static.heap_analysis.instruction_parser import \
    InstructionParser  # noqa: E402

SAMPLE_DIRS = ("heap_samples", "heap_benign_samples")


def compile_dir(samples_dir: str) -> int:
    """编译单个样本目录, 返回成功数."""
    ok = 0
    for entry in sorted(os.listdir(samples_dir)):
        sample_dir = os.path.join(samples_dir, entry)
        src = os.path.join(sample_dir, "src", "vuln.c")
        if not (os.path.isdir(sample_dir) and os.path.isfile(src)):
            continue
        binary = os.path.join(sample_dir, "vuln.exe")
        if os.path.isfile(binary) and \
                os.path.getmtime(binary) >= os.path.getmtime(src):
            ok += 1
            continue
        r = subprocess.run(
            ["gcc", "-Wall", "-O0", "-g", "-no-pie",
             "-fno-stack-protector", "-o", binary, src],
            capture_output=True, text=True, timeout=30)
        if r.returncode == 0:
            ok += 1
        else:
            print(f"  [FAIL] {entry}: {r.stderr[:120]}")
    return ok


def scan_one(exe: str, name: str) -> dict:
    """objdump + GivaScanner, 返回 (baseline_flagged, giva_flagged)."""
    txt = subprocess.run(
        ["objdump", "-d", "-M", "intel", exe],
        capture_output=True, text=True, timeout=60).stdout
    r = GivaScanner(binary_path=exe).scan(txt, name)
    return {"baseline": r["n_baseline_real"] > 0,
            "giva": r["n_real"] > 0}


def main():
    ap = argparse.ArgumentParser(description="FP benchmark (baseline vs giva)")
    ap.add_argument("--skip-compile", action="store_true",
                    help="跳过编译阶段")
    args = ap.parse_args()

    labels = json.load(open(os.path.join(BASE, "sample_labels.json"),
                            encoding="utf-8"))
    t0 = time.perf_counter()

    if not args.skip_compile:
        print("[Phase 1/3] 编译样本 ...")
        for d in SAMPLE_DIRS:
            n = compile_dir(os.path.join(BASE, d))
            print(f"  {d}: {n} 就绪")

    print("[Phase 2/3] 扫描 ...")
    rows = []
    for sub in SAMPLE_DIRS:
        d = os.path.join(BASE, sub)
        for entry in sorted(os.listdir(d)):
            exe = os.path.join(d, entry, "vuln.exe")
            if not os.path.isfile(exe) or entry not in labels:
                continue
            lab = labels[entry].get("heap_overflow", False)
            res = scan_one(exe, entry)
            base_status = ("TP" if lab and res["baseline"] else
                           "FP" if not lab and res["baseline"] else
                           "FN" if lab and not res["baseline"] else "TN")
            giva_status = ("TP" if lab and res["giva"] else
                           "FP" if not lab and res["giva"] else
                           "FN" if lab and not res["giva"] else "TN")
            rows.append({
                "sample": entry, "group": sub,
                "expected": lab, "baseline_flagged": res["baseline"],
                "giva_flagged": res["giva"],
                "baseline_status": base_status,
                "giva_status": giva_status,
            })

    print("[Phase 3/3] 对比 ...")
    stats = {"base": {"tp": 0, "fp": 0, "fn": 0, "tn": 0},
             "giva": {"tp": 0, "fp": 0, "fn": 0, "tn": 0}}
    for r in rows:
        for key, status in (("base", r["baseline_status"]),
                            ("giva", r["giva_status"])):
            stats[key][status.lower()] += 1

    def metrics(s):
        tp, fp, fn, tn = s["tp"], s["fp"], s["fn"], s["tn"]
        prec = tp / (tp + fp) if tp + fp else 1.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        fpr = fp / (fp + tn) if fp + tn else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        return {"precision": round(prec, 4), "recall": round(rec, 4),
                "f1": round(f1, 4), "fp_rate": round(fpr, 4)}

    m_base = metrics(stats["base"])
    m_giva = metrics(stats["giva"])

    print()
    print("=" * 78)
    print("  Heap Overflow — Baseline(absint) vs GIVA(PG-WBV)")
    print("=" * 78)
    print(f"  {'':<6}{'TP':>4}{'FP':>4}{'FN':>4}{'TN':>4}"
          f"{'Prec':>8}{'Recall':>8}{'F1':>7}{'FPR':>8}")
    for key, m in (("base", m_base), ("giva", m_giva)):
        s = stats[key]
        print(f"  {key:<6}{s['tp']:>4}{s['fp']:>4}{s['fn']:>4}{s['tn']:>4}"
              f"{m['precision']:>8.3f}{m['recall']:>8.3f}{m['f1']:>7.3f}"
              f"{m['fp_rate']:>8.3f}")
    print("=" * 78)
    fp_drop = ((m_base["fp_rate"] - m_giva["fp_rate"]) / m_base["fp_rate"]
               if m_base["fp_rate"] > 0 else 0.0)
    fn_fix = stats["base"]["fn"] - stats["giva"]["fn"]
    print(f"  FP 降幅: {m_base['fp_rate'] * 100:.1f}% -> "
          f"{m_giva['fp_rate'] * 100:.1f}% "
          f"(相对下降 {fp_drop * 100:.1f}%)")
    print(f"  FN 修复: baseline {stats['base']['fn']} -> giva "
          f"{stats['giva']['fn']} (修复 {fn_fix} 个漏报)")
    print(f"  总耗时: {time.perf_counter() - t0:.1f}s")

    changed = [r for r in rows if r["baseline_status"] != r["giva_status"]]
    if changed:
        print()
        print("  行为差异样本:")
        for r in changed:
            print(f"    {r['sample']:<34s} {r['baseline_status']} -> "
                  f"{r['giva_status']}")

    out = {"timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
           "metrics": {"baseline_absint": m_base, "giva": m_giva},
           "fp_rate_drop": round(fp_drop, 4),
           "fn_fixed": fn_fix,
           "rows": rows}
    with open(os.path.join(BASE, "fp_benchmark_results.json"), "w") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    with open(os.path.join(BASE, "fp_benchmark_results.csv"), "w",
              newline="") as f:
        f.write("sample,group,expected,baseline_flagged,giva_flagged,"
                "baseline_status,giva_status\n")
        for r in rows:
            f.write(f"{r['sample']},{r['group']},{int(r['expected'])},"
                    f"{int(r['baseline_flagged'])},{int(r['giva_flagged'])},"
                    f"{r['baseline_status']},{r['giva_status']}\n")
    print(f"\n[OK] 结果保存: fp_benchmark_results.json / .csv")
    return 0


if __name__ == "__main__":
    sys.exit(main())
