"""
堆溢出检测回归测试套件 —— 一键运行入口。

流程:
  1. 编译所有样本 (compile_samples.py)
  2. 基线扫描 (run_scanner baseline)
  3. 增强管线扫描 (run_scanner enhanced)
  4. 收集结果 (collect_results.py)
  5. 生成对比报告 (baseline vs enhanced)

输出:
  · results/heap_regression_report.json — 完整报告
  · results/heap_regression_metrics.csv — 指标CSV
  · stdout — Markdown 格式的摘要
"""

import json
import os
import sys
import time
from pathlib import Path

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_RESULTS_DIR = os.path.join(_PROJECT_ROOT, "tests", "results")
_SAMPLES_DIRS = [
    "tests/samples/heap_fp_reduction",
    "tests/heap_overflow_samples",
    "tests/cve_samples_heap",
]


def find_all_samples() -> list[dict]:
    """在所有样本目录中查找编译好的 ELF。"""
    samples = []
    for sdir in _SAMPLES_DIRS:
        full = os.path.join(_PROJECT_ROOT, sdir)
        if not os.path.isdir(full):
            continue
        for root, dirs, files in os.walk(full):
            for f in files:
                if f.startswith("vuln_elf"):
                    binary = os.path.join(root, f)
                    src = os.path.join(root, "vuln.c")
                    samples.append({
                        "name": os.path.basename(root),
                        "directory": root,
                        "binary": binary,
                        "source": src if os.path.isfile(src) else None,
                        "category": os.path.basename(os.path.dirname(root)),
                    })
    return sorted(samples, key=lambda s: s["name"])


def compile_samples(samples: list[dict]) -> dict:
    """编译所有样本。"""
    import subprocess
    results = {"compiled": 0, "failed": 0, "skipped": 0, "details": []}
    for s in samples:
        if not s.get("source") or not os.path.isfile(s["source"]):
            results["skipped"] += 1
            continue
        workdir = s["directory"]
        makefile = os.path.join(workdir, "Makefile")
        detail = {"name": s["name"], "status": "unknown"}
        try:
            if os.path.isfile(makefile):
                subprocess.run(["make", "clean"], cwd=workdir,
                               capture_output=True, timeout=10)
                proc = subprocess.run(["make", "all"], cwd=workdir,
                                      capture_output=True, text=True, timeout=30)
                if proc.returncode == 0 and os.path.isfile(s["binary"]):
                    detail["status"] = "compiled"
                    results["compiled"] += 1
                else:
                    detail["status"] = "failed"
                    detail["error"] = proc.stderr[:200]
                    results["failed"] += 1
            else:
                # 无 Makefile: 直接编译
                proc = subprocess.run(
                    ["gcc", "-O0", "-g", "-Wall", "-o", s["binary"], s["source"]],
                    capture_output=True, text=True, timeout=30,
                )
                if proc.returncode == 0:
                    detail["status"] = "compiled"
                    results["compiled"] += 1
                else:
                    detail["status"] = "failed"
                    detail["error"] = proc.stderr[:200]
                    results["failed"] += 1
        except Exception as e:
            detail["status"] = "failed"
            detail["error"] = str(e)[:200]
            results["failed"] += 1
        results["details"].append(detail)
    return results


def scan_samples(samples: list[dict], mode: str = "enhanced") -> list[dict]:
    """扫描所有样本。"""
    from tests.run_scanner import run_scanner_direct
    results = []
    for s in samples:
        if not os.path.isfile(s["binary"]):
            continue
        r = run_scanner_direct(s["binary"], mode=mode)
        r["sample_name"] = s["name"]
        r["category"] = s["category"]
        results.append(r)
    return results


def classify_result(detected: bool, should_detect: bool) -> str:
    if detected and should_detect: return "TP"
    if detected and not should_detect: return "FP"
    if not detected and should_detect: return "FN"
    return "TN"


def run_full_suite() -> dict:
    """运行完整回归测试套件。"""
    os.makedirs(_RESULTS_DIR, exist_ok=True)
    report = {
        "title": "Heap Overflow Detection Regression Suite",
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "baseline": {}, "enhanced": {}, "comparison": {},
    }

    # 查找样本
    samples = find_all_samples()
    print(f"Found {len(samples)} samples across {len(_SAMPLES_DIRS)} directories")

    # 编译
    compile_result = compile_samples(samples)
    print(f"Compiled: {compile_result['compiled']}/{len(samples)} "
          f"({compile_result['failed']} failed, {compile_result['skipped']} skipped)")

    compiled = [s for s in samples if os.path.isfile(s["binary"])]
    if not compiled:
        print("No compiled binaries found. Aborting scan.")
        return report

    # 基线扫描
    print("\n--- Baseline scan ---")
    baseline_results = scan_samples(compiled, mode="baseline")
    report["baseline"] = _compute_metrics(baseline_results, "baseline")

    # 增强扫描
    print("\n--- Enhanced scan ---")
    enhanced_results = scan_samples(compiled, mode="enhanced")
    report["enhanced"] = _compute_metrics(enhanced_results, "enhanced")

    # 对比
    b = report["baseline"]
    e = report["enhanced"]
    fp_reduction = (b.get("FP", 0) - e.get("FP", 0))
    tp_retention = e.get("TP", 0) / max(b.get("TP", 0), 1)
    report["comparison"] = {
        "fp_reduced": fp_reduction,
        "fp_reduction_rate": fp_reduction / max(b.get("FP", 0), 1),
        "tp_retention_rate": tp_retention,
        "baseline_fp_rate": b.get("fp_rate", 0),
        "enhanced_fp_rate": e.get("fp_rate", 0),
        "summary": (f"FP: {b.get('FP', 0)} → {e.get('FP', 0)} "
                    f"({fp_reduction} reduced). "
                    f"TP retention: {tp_retention:.0%}. "
                    f"FP rate: {b.get('fp_rate', 0):.1%} → {e.get('fp_rate', 0):.1%}"),
    }

    # 保存
    report_path = os.path.join(_RESULTS_DIR, "heap_regression_report.json")
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    # 打印
    _print_report(report)
    return report


def _compute_metrics(results: list[dict], mode: str) -> dict:
    """从扫描结果计算指标。"""
    from tests.collect_results import EXPECTED_MAP
    tp = fp = tn = fn_count = 0
    details = []

    for r in results:
        name = r.get("sample", r.get("sample_name", ""))
        detected = r.get("detected", r.get("candidates", 0) > 0)
        exp = EXPECTED_MAP.get(name)
        should_detect = exp[1] if exp else True
        verdict = classify_result(detected, should_detect)
        if verdict == "TP": tp += 1
        elif verdict == "FP": fp += 1
        elif verdict == "TN": tn += 1
        else: fn_count += 1
        details.append({
            "name": name, "detected": detected,
            "should_detect": should_detect, "verdict": verdict,
            "confidence": r.get("confidence", 0.0),
            "duration_ms": r.get("duration_ms", 0),
        })

    total = len(details)
    return {
        "mode": mode, "total": total,
        "TP": tp, "FP": fp, "TN": tn, "FN": fn_count,
        "precision": tp / max(tp + fp, 1),
        "recall": tp / max(tp + fn_count, 1),
        "fp_rate": fp / max(fp + tn, 1),
        "f1": 0.0 if (tp + fp + fn_count) == 0 else round(
            2 * tp / max(2 * tp + fp + fn_count, 1), 4),
        "details": details,
    }


def _print_report(report: dict):
    """打印 Markdown 格式的对比报告。"""
    c = report["comparison"]
    b = report["baseline"]
    e = report["enhanced"]
    print(f"\n## 堆溢出检测回归测试报告")
    print(f"生成时间: {report['generated_at']}")
    print()
    print(f"| 模式 | TP | FP | TN | FN | Precision | Recall | FP Rate | F1 |")
    print(f"|------|----|----|----|----|-----------|--------|---------|-----|")
    for r, label in [(b, "Baseline"), (e, "Enhanced")]:
        print(f"| {label} | {r['TP']} | {r['FP']} | {r['TN']} | {r['FN']} "
              f"| {r['precision']:.1%} | {r['recall']:.1%} "
              f"| {r['fp_rate']:.1%} | {r['f1']:.4f} |")
    print()
    print(f"**FP Reduction:** {c['fp_reduced']} "
          f"({c['fp_reduction_rate']:.0%})")
    print(f"**TP Retention:** {c['tp_retention_rate']:.0%}")
    print(f"**Summary:** {c['summary']}")


if __name__ == '__main__':
    run_full_suite()
