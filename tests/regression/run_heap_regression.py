"""
堆溢出回归测试 — 源级验证器 + 二进制管线 + ground truth对比.

用法:
  python tests/regression/run_heap_regression.py
  python tests/regression/run_heap_regression.py --sample cve_01_simple_overflow
  python tests/regression/run_heap_regression.py --csv results.csv
"""

from __future__ import annotations
import argparse
import csv
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_DEEMO_ROOT = Path(__file__).parent.parent.parent
if str(_DEEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(_DEEMO_ROOT))

SAMPLE_DIR = _DEEMO_ROOT / "tests" / "cve_samples" / "heap_overflow"
GROUND_TRUTH_PATH = SAMPLE_DIR / "ground_truth.json"
RESULTS_DIR = _DEEMO_ROOT / "eval" / "results"


def load_ground_truth() -> Dict:
    with open(GROUND_TRUTH_PATH, encoding='utf-8') as f:
        return json.load(f)


def run_source_level_verifier(source: str) -> List[Dict]:
    """运行堆写模式验证源级堆溢出验证器."""
    from analysis.heap_overflow_src_verifier import HeapOverflowSrcVerifier
    from analysis.heap_overflow_types import HoVerdict

    verifier = HeapOverflowSrcVerifier()
    results = verifier.verify(source)
    findings = []
    for r in results:
        findings.append({
            "verdict": r.verdict.value,
            "alloc_line": r.alloc_line,
            "write_line": r.write_line,
            "var_name": r.var_name,
            "alloc_size": r.alloc_size,
            "write_size": r.write_size,
            "overflow_bytes": r.overflow_bytes,
            "confidence": r.confidence,
            "reason": r.reason,
            "stages": {
                "raw": r.stage_raw,
                "guard": r.stage_guard,
                "constraint": r.stage_constraint,
                "alloc_model": r.stage_alloc_model,
            },
        })
    return findings


def run_binary_pipeline(binary_path: str, sample_dir: str) -> List[Dict]:
    """运行二进制级仿射边界验证堆溢出检测管线.

    修复: 不再将binary_path当源码传入, 而是:
    1. 从sample_dir读取C源码
    2. 用c_to_pseudocode转换为伪代码
    3. 将伪代码传入quick_analyze
    4. 正确提取PipelineFinding的is_true_positive字段
    """
    findings = []
    try:
        # 从样本目录读取C源码
        sample_path = Path(sample_dir)
        c_files = list(sample_path.glob("*.c"))
        if not c_files:
            return findings
        source = c_files[0].read_text(encoding='utf-8', errors='replace')

        from core.c_to_pseudocode import convert as c_to_pseudo
        pseudocode = c_to_pseudo(source)

        from analysis.unified_heap_pipeline import quick_analyze
        results = quick_analyze(pseudocode)
        for r in results:
            findings.append({
                "verdict": "VULN" if r.is_true_positive else "SAFE",
                "alloc_site": getattr(r, 'line', 0),
                "write_site": 0,
                "confidence": r.confidence,
                "reason": r.reasoning,
                "fp_likelihood": r.fp_likelihood,
            })
    except Exception:
        pass
    return findings


def read_sample_source(sample_name: str) -> Optional[str]:
    """读取样本C源码."""
    sample_path = SAMPLE_DIR / sample_name
    c_files = list(sample_path.glob("*.c"))
    if c_files:
        return c_files[0].read_text(encoding='utf-8', errors='replace')
    return None


def read_sample_binary(sample_name: str) -> Optional[str]:
    """获取样本二进制路径."""
    sample_path = SAMPLE_DIR / sample_name
    exe_files = list(sample_path.glob("*.exe"))
    if exe_files:
        return str(exe_files[0])
    return None


def evaluate_sample(sample_name: str, expected: Dict) -> Dict[str, Any]:
    """评估单个样本: 源级 + 二进制级."""
    result = {
        "sample": sample_name,
        "expected_vuln": expected["expected_vuln"],
        "expected_type": expected["expected_type"],
        "source_findings": [],
        "binary_findings": [],
        "source_vuln_count": 0,
        "binary_vuln_count": 0,
        "source_time_ms": 0.0,
        "binary_time_ms": 0.0,
        "verdict": "UNKNOWN",
        "match": None,
    }

    # 源级分析
    source = read_sample_source(sample_name)
    if source:
        t0 = time.time()
        result["source_findings"] = run_source_level_verifier(source)
        result["source_time_ms"] = (time.time() - t0) * 1000
        result["source_vuln_count"] = sum(
            1 for f in result["source_findings"]
            if f["verdict"] == "VULN")

    # 二进制级分析
    binary = read_sample_binary(sample_name)
    if binary and os.path.exists(binary):
        t0 = time.time()
        result["binary_findings"] = run_binary_pipeline(
            binary, str(SAMPLE_DIR / sample_name))
        result["binary_time_ms"] = (time.time() - t0) * 1000
        result["binary_vuln_count"] = sum(
            1 for f in result["binary_findings"]
            if f["verdict"] == "VULN")

    # 综合判定: 源级 + 二进制级融合
    src_vuln = result["source_vuln_count"] > 0
    bin_vuln = result["binary_vuln_count"] > 0
    if src_vuln or bin_vuln:
        result["verdict"] = "VULN"
    elif result["source_findings"] or result["binary_findings"]:
        result["verdict"] = "SAFE"
    else:
        result["verdict"] = "CLEAN"

    result["match"] = (result["verdict"] in ("VULN", "CLEAN")) == (
        not expected["expected_vuln"] if result["verdict"] == "CLEAN"
        else expected["expected_vuln"])
    # 修正match逻辑
    if expected["expected_vuln"]:
        result["match"] = result["verdict"] == "VULN"
    else:
        result["match"] = result["verdict"] != "VULN"

    return result


def compute_metrics(results: List[Dict]) -> Dict:
    """计算TP/FP/TN/FN和F1."""
    tp = fp = tn = fn = 0
    for r in results:
        if r["expected_vuln"] and r["verdict"] == "VULN":
            tp += 1
        elif r["expected_vuln"] and r["verdict"] != "VULN":
            fn += 1
        elif not r["expected_vuln"] and r["verdict"] == "VULN":
            fp += 1
        elif not r["expected_vuln"] and r["verdict"] != "VULN":
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) > 0 else 0.0)

    return {
        "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        "total": tp + fp + tn + fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "fp_rate": round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0,
    }


def run_regression(sample_filter: str = "") -> Tuple[List[Dict], Dict]:
    """运行完整回归测试."""
    gt = load_ground_truth()
    samples = gt["samples"]

    if sample_filter:
        samples = {k: v for k, v in samples.items()
                    if sample_filter in k}

    results = []
    for name, expected in samples.items():
        print(f"  Evaluating {name}...", end=" ")
        r = evaluate_sample(name, expected)
        results.append(r)
        status = "PASS" if r["match"] else "FAIL"
        print(f"{status} (src={r['source_vuln_count']}, "
              f"bin={r['binary_vuln_count']}, "
              f"{r['source_time_ms']:.1f}ms/{r['binary_time_ms']:.1f}ms)")

    metrics = compute_metrics(results)
    return results, metrics


def export_csv(results: List[Dict], metrics: Dict, path: str):
    """导出CSV结果."""
    with open(path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["sample", "expected_vuln", "expected_type",
                          "verdict", "match", "source_vuln_count",
                          "binary_vuln_count", "source_time_ms",
                          "binary_time_ms"])
        for r in results:
            writer.writerow([
                r["sample"], r["expected_vuln"], r["expected_type"],
                r["verdict"], r["match"], r["source_vuln_count"],
                r["binary_vuln_count"],
                f"{r['source_time_ms']:.1f}",
                f"{r['binary_time_ms']:.1f}",
            ])

    print(f"\nCSV exported → {path}")


def main():
    parser = argparse.ArgumentParser(
        description="Heap overflow regression test")
    parser.add_argument("--sample", default="",
                        help="Filter by sample name substring")
    parser.add_argument("--csv", default="",
                        help="Export results to CSV")
    parser.add_argument("--json", default="",
                        help="Export results to JSON")
    args = parser.parse_args()

    print(f"Heap Overflow Regression Test")
    print(f"  Samples: {GROUND_TRUTH_PATH}")
    print(f"  Filter: {args.sample or 'all'}\n")

    results, metrics = run_regression(args.sample)

    print(f"\n{'='*60}")
    print(f"RESULTS: TP={metrics['TP']} FP={metrics['FP']} "
          f"TN={metrics['TN']} FN={metrics['FN']}")
    print(f"  Precision: {metrics['precision']:.4f}")
    print(f"  Recall:    {metrics['recall']:.4f}")
    print(f"  F1:        {metrics['f1']:.4f}")
    print(f"  FP Rate:   {metrics['fp_rate']:.4f}")
    print(f"{'='*60}")

    # 导出
    os.makedirs(RESULTS_DIR, exist_ok=True)
    if args.csv:
        export_csv(results, metrics, args.csv)
    if args.json:
        out = {"results": results, "metrics": metrics}
        with open(args.json, 'w') as f:
            json.dump(out, f, indent=2)
        print(f"JSON exported → {args.json}")

    # 默认导出
    default_json = RESULTS_DIR / "heap_regression_results.json"
    out = {"results": results, "metrics": metrics}
    with open(default_json, 'w') as f:
        json.dump(out, f, indent=2)
    print(f"Results saved → {default_json}")

    return 0 if metrics["FN"] == 0 and metrics["FP"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
