# -*- coding: utf-8 -*-
#
"""
UAF 多工具对比基准 (O0 / O2 双变体)。

工具:
  1. UAF-PROV (本方法) —— 内联调用 uafprov 管线
  2. Angr 符号执行        —— angr_explorer.py
  3. QEMU 动态追踪        —— qemu_tracer.py
  4. Ghidra 无头静态审计  —— ghidra_headless.py

输出 benchmark_results.csv / benchmark_results.json。
"""

import argparse
import csv
import json
import subprocess
import sys
from pathlib import Path

_EVAL = Path(__file__).resolve().parent
_ROOT = _EVAL.parents[1]
_CORPUS = _ROOT / "deemo" / "modules" / "vuln" / "test_samples" / "uaf_cve"
_DETECT = _ROOT / "deemo" / "modules" / "vuln" / "detection"
sys.path.insert(0, str(_DETECT))

O2_CFLAGS = ["-Wall", "-O2", "-fno-builtin", "-fno-stack-protector",
             "-no-pie"]


def load_expected() -> dict:
    gt = {}
    f = _CORPUS / "expected.csv"
    if f.exists():
        with open(f, newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                gt[row["sample_id"]] = row["expected"]
    return gt


def ensure_o2(sample_dir: Path):
    out = sample_dir / "vuln_o2.exe"
    if not out.exists():
        r = subprocess.run(["gcc"] + O2_CFLAGS +
                           ["-o", str(out), str(sample_dir / "vuln.c")],
                           capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            return None
    return out


def run_uafprov(binary: Path) -> dict:
    from uafprov.pipeline import UafProvenancePipeline
    import time
    pipe = UafProvenancePipeline()
    t0 = time.time()
    rep = pipe.analyze_binary(str(binary))
    ms = round((time.time() - t0) * 1000, 1)
    return {"detected": rep.detected, "ms": ms, "pairs": rep.n_pairs,
            "n_uaf": rep.n_uaf, "n_safe": rep.n_safe}


def run_tool(script: Path, variant: str) -> list:
    cmd = [sys.executable, str(script), "--batch", "--variant", variant,
           "--samples-dir", str(_CORPUS)]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=600,
                       cwd=str(_EVAL))
        for cand in (_EVAL / f"{script.stem.split('_')[0]}_results.json",
                     _EVAL / f"{script.stem}_results.json"):
            if cand.exists():
                return json.loads(cand.read_text(encoding="utf-8")) \
                    .get("results", [])
    except Exception:
        pass
    return []


def _verdict(det, exp):
    if exp == "TP":
        return "TP" if det else "FN"
    return "FP" if det else "TN"


def _write_csv(rows):
    fields = ["tool", "sample", "variant", "expected", "detected",
              "verdict", "time_ms", "peak_mem_mb", "detail"]
    with open(_EVAL / "uaf_benchmark_results.csv", "w", newline="",
              encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def _summarize(rows):
    per = {}
    for t in sorted({r["tool"] for r in rows}):
        tr = [r for r in rows if r["tool"] == t]
        tp = sum(1 for r in tr if r["verdict"] == "TP")
        tn = sum(1 for r in tr if r["verdict"] == "TN")
        fp = sum(1 for r in tr if r["verdict"] == "FP")
        fn = sum(1 for r in tr if r["verdict"] == "FN")
        p = tp / max(1, tp + fp)
        r_ = tp / max(1, tp + fn)
        per[t] = {"tp": tp, "tn": tn, "fp": fp, "fn": fn,
                  "precision": round(p, 3), "recall": round(r_, 3),
                  "f1": round(2 * p * r_ / max(.001, p + r_), 3),
                  "fpr": round(fp / max(1, fp + tn), 3),
                  "avg_time_ms": round(
                      sum(x["time_ms"] for x in tr) / max(1, len(tr)), 1),
                  "n": len(tr)}
    return per


def main() -> int:
    ap = argparse.ArgumentParser(description="UAF multi-tool benchmark")
    ap.add_argument("--skip", type=str, default="")
    args = ap.parse_args()
    skip = {s.strip() for s in args.skip.split(",") if s.strip()}
    gt = load_expected()
    samples = sorted(d for d in _CORPUS.iterdir()
                     if d.is_dir() and (d / "vuln.c").exists())
    rows = []

    for d in samples:
        for v, name in (("O0", "vuln.exe"), ("O2", None)):
            binary = d / name if v == "O0" else ensure_o2(d)
            if binary is None or not binary.exists():
                continue
            g = run_uafprov(binary)
            det = g["detected"]
            rows.append({
                "tool": "UAF-PROV", "sample": d.name, "variant": v,
                "expected": gt.get(d.name, "TP"), "detected": det,
                "verdict": _verdict(det, gt.get(d.name, "TP")),
                "time_ms": g["ms"], "peak_mem_mb": 0,
                "detail": f"pairs={g['pairs']} safe={g['n_safe']}"})
            print(f"  [UAF-PROV] {d.name:28s} {v} detected={det} {g['ms']}ms")

    for key, script_name in (("angr", "angr_explorer.py"),
                             ("qemu", "qemu_tracer.py"),
                             ("ghidra", "ghidra_headless.py")):
        if key in skip:
            continue
        script = _EVAL / script_name
        if not script.exists():
            continue
        for v in ("O0", "O2"):
            res = run_tool(script, v)
            for r in res:
                det = r.get("overflow_detected", False) or r.get(
                    "detected", False)
                sid = r.get("sample_id", "?")
                rows.append({
                    "tool": key.title(), "sample": sid, "variant": v,
                    "expected": gt.get(sid, "TP"), "detected": det,
                    "verdict": _verdict(det, gt.get(sid, "TP")),
                    "time_ms": round(r.get("elapsed_sec", 0) * 1000, 1),
                    "peak_mem_mb": 0,
                    "detail": f"mode={r.get('mode', '?')}"})

    _write_csv(rows)
    report = {"tools": _summarize(rows),
              "n_samples": len(samples),
              "variants": ["O0", "O2"]}
    (_CORPUS / "benchmark_results.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print("\n===== SUMMARY (O0+O2) =====")
    for t, m in report["tools"].items():
        print(f"{t:9s} TP={m['tp']:2d} TN={m['tn']:2d} FP={m['fp']:2d} "
              f"FN={m['fn']:2d} P={m['precision']:.3f} R={m['recall']:.3f} "
              f"F1={m['f1']:.3f} FPR={m['fpr']:.3f} "
              f"{m['avg_time_ms']:.1f}ms")
    return 0


if __name__ == "__main__":
    sys.exit(main())
