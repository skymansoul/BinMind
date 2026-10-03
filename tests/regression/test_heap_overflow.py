# 堆溢出回归测试 — 编译→扫描→统计检出/误报/漏报
# 用法: python test_heap_overflow.py [--skip-compile] [--with-filter]

import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).parent
SAMPLES = HERE / "samples_heap"
BUILD = HERE / "build_heap"
RESULTS = HERE / "results_heap"


def compile_all():
    BUILD.mkdir(exist_ok=True)
    ok = 0
    for d in sorted(SAMPLES.iterdir()):
        if not d.is_dir() or not (d / "vuln.c").exists():
            continue
        src = d / "vuln.c"
        out = BUILD / d.name
        out.mkdir(exist_ok=True)
        binary = out / "vuln"
        cmd = f"gcc -g -O0 -no-pie -fno-stack-protector -o {binary} {src}"
        r = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=30)
        if r.returncode == 0 and binary.exists():
            ok += 1
    print(f"Compiled: {ok} samples")
    return ok


def scan_all(with_filter=True):
    binaries = []
    for d in sorted(BUILD.iterdir()):
        if not d.is_dir():
            continue
        b = d / "vuln"
        if b.exists():
            binaries.append((d.name, str(b)))

    results = []
    for name, path in binaries:
        t0 = time.perf_counter()
        findings = []
        try:
            from core.vuln_analyzer import analyze_all
            findings = analyze_all(path)
            if with_filter:
                from core.heap_fp_filter import apply_fp_filters
                findings = apply_fp_filters(findings, [])
        except Exception as e:
            pass
        elapsed = time.perf_counter() - t0
        results.append({
            "sample": name, "binary": path,
            "findings": len(findings), "time_s": round(elapsed, 2),
            "details": [f.get("type", "?") for f in findings[:5]],
        })
    return results


def compute_stats(results, gt_path=None):
    gt = {}
    if gt_path and os.path.exists(gt_path):
        with open(gt_path) as f:
            gt = json.load(f)

    tp = fp = fn = 0
    for r in results:
        name = r["sample"]
        expected = gt.get(name, ["heap_overflow"])
        detected = r["findings"] > 0
        if detected:
            if any(e in str(r.get("details", [])) for e in expected):
                tp += 1
            else:
                fp += 1
        else:
            if expected:
                fn += 1

    n = max(1, tp + fn)
    return {
        "total": len(results), "tp": tp, "fp": fp, "fn": fn,
        "detection_rate": round(tp / n, 3),
        "fp_rate": round(fp / max(1, tp + fp), 3),
        "avg_time_s": round(sum(r["time_s"] for r in results) / max(1, len(results)), 1),
    }


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--skip-compile", action="store_true")
    p.add_argument("--no-filter", action="store_true")
    args = p.parse_args()

    if not args.skip_compile:
        compile_all()

    t0 = time.time()
    results = scan_all(with_filter=not args.no_filter)
    stats = compute_stats(results)

    RESULTS.mkdir(exist_ok=True)
    with open(RESULTS / "heap_results.json", "w") as f:
        json.dump({"stats": stats, "results": results}, f, indent=2)

    print(f"\nDetection rate: {stats['detection_rate']:.1%}")
    print(f"FP rate: {stats['fp_rate']:.1%}")
    print(f"Avg time: {stats['avg_time_s']}s")
    print(f"Total: {time.time()-t0:.1f}s")
