# -*- coding: utf-8 -*-
# 创建: 2026-05-11  |  多工具对比基准——主实验编排
#
"""
多工具对比基准主脚本。

在 CVE 堆溢出语料上运行 4 类工具 (每个样本 O0 / O2 两种变体):
  1. GASRI (本方法)         —— 直接内联调用 heapver 管线
  2. Angr 符号执行探索       —— angr_explorer.py
  3. QEMU 动态追踪           —— qemu_tracer.py
  4. Ghidra 无头静态审计     —— ghidra_headless.py

输出:
  benchmark_results.csv   统一格式: 工具,样本,变体,期望,检出,判定,耗时,内存
  benchmark_results.json  汇总指标 (每工具 Recall/Precision/F1/FPR)

运行:
  python run_benchmark.py
  python run_benchmark.py --skip angr,qemu,ghidra   # 仅 GASRI
  python run_benchmark.py --samples-dir DIR
"""

import argparse
import csv
import json
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional

_EVAL = Path(__file__).resolve().parent
_ROOT = _EVAL.parents[1]
_CORPUS = _ROOT / "deemo" / "modules" / "vuln" / "test_samples" / "cve_heap"
_HEAPVER = _ROOT / "deemo" / "modules" / "vuln" / "detection"

sys.path.insert(0, str(_HEAPVER))

O2_CFLAGS = ["-Wall", "-O2", "-fno-builtin", "-fno-stack-protector",
             "-no-pie"]


def load_expected() -> Dict[str, str]:
    gt = {}
    f = _CORPUS / "expected.csv"
    if f.exists():
        with open(f, newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                gt[row["sample_id"]] = row["expected"]
    return gt


def ensure_o2(sample_dir: Path) -> Optional[Path]:
    """编译 O2 变体, 返回二进制路径."""
    src = sample_dir / "vuln.c"
    out = sample_dir / "vuln_o2.exe"
    if not out.exists() or out.stat().st_mtime < src.stat().st_mtime:
        r = subprocess.run(["gcc"] + O2_CFLAGS + ["-o", str(out), str(src)],
                           capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            return None
    return out if out.exists() else None


def run_gasri(binary: Path, variant: str) -> dict:
    from heapver.pipeline import GASRIPipeline
    pipe = GASRIPipeline()
    t0 = time.time()
    rep = pipe.analyze_binary(str(binary))
    ms = round((time.time() - t0) * 1000, 1)
    return {"detected": rep.detected, "ms": ms, "pairs": rep.n_pairs,
            "n_safe": rep.n_safe, "n_overflow": rep.n_overflow,
            "n_suspicious": rep.n_suspicious}


def run_tool_script(script: Path, variant: str,
                    timeout_s: int = 600) -> List[dict]:
    """运行子工具脚本 --batch --variant, 返回结果列表."""
    cmd = [sys.executable, str(script), "--batch", "--variant", variant,
           "--samples-dir", str(_CORPUS)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout_s, cwd=str(_EVAL))
        candidates = [
            _EVAL / f"{script.stem}_results.json",
            _EVAL / f"{script.stem.split('_')[0]}_results.json",
            Path(".") / f"{script.stem}_results.json",
            Path(".") / f"{script.stem.split('_')[0]}_results.json",
        ]
        for out_json in candidates:
            if out_json.exists():
                data = json.loads(out_json.read_text(encoding="utf-8"))
                return data.get("results", [])
        return []
    except Exception:
        return []


def main() -> int:
    ap = argparse.ArgumentParser(description="multi-tool heap overflow benchmark")
    ap.add_argument("--skip", type=str, default="",
                    help="comma list: angr,qemu,ghidra")
    ap.add_argument("--samples-dir", type=str, default=str(_CORPUS))
    args = ap.parse_args()
    skip = {s.strip() for s in args.skip.split(",") if s.strip()}

    gt = load_expected()
    samples = sorted(d for d in Path(args.samples_dir).iterdir()
                     if d.is_dir() and (d / "vuln.c").exists())
    variants = ["O0", "O2"]

    rows = []

# GASRI (内联, 精确)
    for d in samples:
        for v in variants:
            binary = d / "vuln.exe" if v == "O0" else ensure_o2(d)
            if binary is None or not binary.exists():
                continue
            g = run_gasri(binary, v)
            rows.append({
                "tool": "GASRI", "sample": d.name, "variant": v,
                "expected": gt.get(d.name, "TP"),
                "detected": g["detected"],
                "verdict": _verdict(g["detected"], gt.get(d.name, "TP")),
                "time_ms": g["ms"], "peak_mem_mb": 0,  # TODO: 采集子进程峰值内存
                "detail": f"pairs={g['pairs']} safe={g['n_safe']}",
            })
            print(f"  [GASRI] {d.name:32s} {v} detected={g['detected']} "
                  f"{g['ms']}ms")

# 外部工具
    tools = {
        "angr": "angr_explorer.py",
        "qemu": "qemu_tracer.py",
        "ghidra": "ghidra_headless.py",
    }
    for key, script_name in tools.items():
        if key in skip:
            continue
        script = _EVAL / script_name
        if not script.exists():
            continue
        for v in variants:
            print(f"\n===== {script_name} ({v}) =====")
            res = run_tool_script(script, v)
            for r in res:
                det = r.get("overflow_detected", False) or r.get(
                    "detected", False)
                sid = r.get("sample_id", "?")
                rows.append({
                    "tool": key.title(), "sample": sid, "variant": v,
                    "expected": gt.get(sid, "TP"),
                    "detected": det,
                    "verdict": _verdict(det, gt.get(sid, "TP")),
                    "time_ms": round(r.get("elapsed_sec", 0) * 1000, 1),
                    "peak_mem_mb": 0,
                    "detail": f"mode={r.get('mode','?')} {r.get('notes','')}",
                })
                print(f"  [{key.title():6s}] {sid:30s} {v} "
                      f"detected={det} mode={r.get('mode','?')}")

    _write_csv(rows)
    report = _summarize(rows)
    (Path(args.samples_dir) / "benchmark_results.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nCSV: {_EVAL / 'benchmark_results.csv'}")
    print(f"JSON: {Path(args.samples_dir) / 'benchmark_results.json'}")
    _print_summary(report)
    return 0


def _verdict(detected: bool, expected: str) -> str:
    if expected == "TP":
        return "TP" if detected else "FN"
    return "FP" if detected else "TN"


def _write_csv(rows: List[dict]) -> None:
    path = _EVAL / "benchmark_results.csv"
    fields = ["tool", "sample", "variant", "expected", "detected",
              "verdict", "time_ms", "peak_mem_mb", "detail"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def _summarize(rows: List[dict]) -> dict:
    tools = sorted({r["tool"] for r in rows})
    per = {}
    for t in tools:
        tr = [r for r in rows if r["tool"] == t]
        tp = sum(1 for r in tr if r["verdict"] == "TP")
        tn = sum(1 for r in tr if r["verdict"] == "TN")
        fp = sum(1 for r in tr if r["verdict"] == "FP")
        fn = sum(1 for r in tr if r["verdict"] == "FN")
        precision = tp / max(1, tp + fp)
        recall = tp / max(1, tp + fn)
        f1 = 2 * precision * recall / max(0.001, precision + recall)
        fpr = fp / max(1, fp + tn)
        avg_ms = sum(r["time_ms"] for r in tr) / max(1, len(tr))
        per[t] = {"tp": tp, "tn": tn, "fp": fp, "fn": fn,
                  "precision": round(precision, 3),
                  "recall": round(recall, 3), "f1": round(f1, 3),
                  "fpr": round(fpr, 3), "avg_time_ms": round(avg_ms, 1),
                  "n": len(tr)}
    return {"tools": per, "n_samples": len({r["sample"] for r in rows}),
            "variants": sorted({r["variant"] for r in rows})}


def _print_summary(report: dict) -> None:
    print("\n===== SUMMARY (O0+O2 combined) =====")
    print(f"{'tool':8s} {'TP':>3s} {'TN':>3s} {'FP':>3s} {'FN':>3s} "
          f"{'P':>7s} {'R':>7s} {'F1':>6s} {'FPR':>6s} {'ms':>8s}")
    for t, m in report["tools"].items():
        print(f"{t:8s} {m['tp']:3d} {m['tn']:3d} {m['fp']:3d} {m['fn']:3d} "
              f"{m['precision']:7.3f} {m['recall']:7.3f} {m['f1']:6.3f} "
              f"{m['fpr']:6.3f} {m['avg_time_ms']:8.1f}")


if __name__ == "__main__":
    sys.exit(main())
