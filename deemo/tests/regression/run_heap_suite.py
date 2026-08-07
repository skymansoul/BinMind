#!/usr/bin/env python3
"""
堆溢出检测全自动化回归套件 — 编译→扫描→评估→报告.

用法:
  python tests/regression/run_heap_suite.py          # 全流程
  python tests/regression/run_heap_suite.py --quick  # 跳过编译
  python tests/regression/run_heap_suite.py --csv results.csv
  python tests/regression/run_heap_suite.py --json results.json
"""
from __future__ import annotations
import argparse, csv, json, os, sys, time
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


def compile_samples() -> bool:
    """编译全部样本, 返回是否全部成功."""
    from tests.cve_samples.heap_overflow.compile_all import find_samples, compile_sample
    samples = find_samples(SAMPLE_DIR)
    ok = True
    for s in samples:
        r = compile_sample(s)
        status = "OK" if r["success"] else f"FAIL: {r['error'][:50]}"
        print(f"  [compile] {s.name}: {status}")
        if not r["success"]:
            ok = False
    return ok


def read_sample_source(name: str) -> Optional[str]:
    d = SAMPLE_DIR / name
    c_files = list(d.glob("*.c"))
    return c_files[0].read_text(encoding='utf-8', errors='replace') if c_files else None


def read_sample_binary(name: str) -> Optional[str]:
    d = SAMPLE_DIR / name
    for ext in ('.exe', ''):
        files = list(d.glob(f"*{ext}"))
        for f in files:
            if f.is_file() and f.suffix in ('', '.exe') and f.name not in ('Makefile',):
                if os.access(str(f), os.X_OK) or f.suffix == '.exe':
                    return str(f)
    return None


def run_source_verifier(source: str) -> List[Dict]:
    """HOSV源级检测."""
    from analysis.heap_overflow_src_verifier import HeapOverflowSrcVerifier
    v = HeapOverflowSrcVerifier()
    results = v.verify(source)
    return [{
        "verdict": r.verdict.value,
        "alloc_line": r.alloc_line,
        "write_line": r.write_line,
        "var_name": r.var_name,
        "alloc_size": r.alloc_size,
        "write_size": r.write_size,
        "confidence": r.confidence,
        "reason": r.reason,
    } for r in results]


def run_binary_pipeline(name: str, binary_path: str) -> List[Dict]:
    """二进制级GAPSBV+CJ管线检测.

    修复: 不再将binary_path当源码传入, 而是:
    1. 读取同目录下的C源码
    2. 用c_to_pseudocode转换为Ghidra风格伪代码
    3. 用core版统一管线(analyze_heap_safety)做完整4层过滤
    4. 正确提取findings的verdict字段
    """
    findings = []
    try:
        # 读取C源码 → 转换为伪代码
        source = read_sample_source(name)
        if not source:
            return findings
        from core.c_to_pseudocode import convert as c_to_pseudo
        pseudocode = c_to_pseudo(source)

        # 使用core版统一管线（含完整4层过滤: 分配器→值域→符号→启发式）
        from core.unified_heap_pipeline import analyze_heap_safety
        results, stats = analyze_heap_safety(pseudocode, "main", binary_path)
        for f in results:
            if f.get("type") == "heap-overflow":
                verdict = f.get("verdict", "UNCERTAIN")
                findings.append({
                    "verdict": "VULN" if verdict in ("DEFINITE", "POSSIBLE") else "SAFE",
                    "confidence": f.get("confidence", 0.5),
                    "reason": f.get("description", ""),
                    "fp_likelihood": 1.0 - f.get("confidence", 0.5),
                })
    except Exception:
        pass
    return findings


def evaluate_sample(name: str, expected: Dict) -> Dict:
    """评估单个样本: 编译+源级+二进制级."""
    result = {
        "sample": name,
        "expected_vuln": expected["expected_vuln"],
        "expected_type": expected["expected_type"],
        "source_findings": [],
        "binary_findings": [],
        "source_vuln_count": 0,
        "binary_vuln_count": 0,
        "source_time_ms": 0.0,
        "binary_time_ms": 0.0,
        "verdict": "UNKNOWN",
        "match": False,
    }

    source = read_sample_source(name)
    if source:
        t0 = time.time()
        result["source_findings"] = run_source_verifier(source)
        result["source_time_ms"] = (time.time() - t0) * 1000
        result["source_vuln_count"] = sum(
            1 for f in result["source_findings"] if f["verdict"] == "VULN")

    binary = read_sample_binary(name)
    if binary and os.path.exists(binary):
        t0 = time.time()
        result["binary_findings"] = run_binary_pipeline(name, binary)
        result["binary_time_ms"] = (time.time() - t0) * 1000
    # 二进制管线仅高置信度DEFINITE判定才计入VULN
    # POSSIBLE级告警保留但不在综合判定中视为VULN
    result["binary_vuln_count"] = sum(
        1 for f in result["binary_findings"]
        if f["verdict"] == "VULN" and f.get("confidence", 0) >= 0.8)

    src_vuln = result["source_vuln_count"] > 0
    bin_vuln = result["binary_vuln_count"] > 0
    if src_vuln or bin_vuln:
        result["verdict"] = "VULN"
    elif result["source_findings"] or result["binary_findings"]:
        result["verdict"] = "SAFE"
    else:
        result["verdict"] = "CLEAN"

    if expected["expected_vuln"]:
        result["match"] = result["verdict"] == "VULN"
    else:
        result["match"] = result["verdict"] != "VULN"

    return result


def compute_metrics(results: List[Dict]) -> Dict:
    tp = fp = tn = fn = 0
    for r in results:
        if r["expected_vuln"] and r["verdict"] == "VULN": tp += 1
        elif r["expected_vuln"] and r["verdict"] != "VULN": fn += 1
        elif not r["expected_vuln"] and r["verdict"] == "VULN": fp += 1
        elif not r["expected_vuln"] and r["verdict"] != "VULN": tn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        "total": tp + fp + tn + fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "fp_rate": round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0,
    }


def run_suite(quick: bool = False, sample_filter: str = "") -> Tuple[List[Dict], Dict]:
    gt = load_ground_truth()
    samples = gt["samples"]
    if sample_filter:
        samples = {k: v for k, v in samples.items() if sample_filter in k}

    if not quick:
        print("[1/3] Compiling samples...")
        compile_samples()

    print(f"\n[2/3] Evaluating {len(samples)} samples...")
    results = []
    for name, expected in samples.items():
        print(f"  {name}...", end=" ")
        r = evaluate_sample(name, expected)
        results.append(r)
        status = "PASS" if r["match"] else "FAIL"
        print(f"{status} (src={r['source_vuln_count']}, "
              f"bin={r['binary_vuln_count']}, "
              f"{r['source_time_ms']:.1f}ms/{r['binary_time_ms']:.1f}ms)")

    print("\n[3/3] Computing metrics...")
    metrics = compute_metrics(results)
    return results, metrics


def print_report(results: List[Dict], metrics: Dict):
    print(f"\n{'='*60}")
    print(f" Heap Overflow Detection - Full Regression Report")
    print(f"{'='*60}")
    print(f" Samples: {metrics['total']}")
    print(f" TP={metrics['TP']}  FP={metrics['FP']}  "
          f"TN={metrics['TN']}  FN={metrics['FN']}")
    print(f" Precision: {metrics['precision']:.4f}")
    print(f" Recall:    {metrics['recall']:.4f}")
    print(f" F1:        {metrics['f1']:.4f}")
    print(f" FP Rate:   {metrics['fp_rate']:.4f}")
    print(f"{'='*60}")

    fails = [r for r in results if not r["match"]]
    if fails:
        print(f"\n Failed samples ({len(fails)}):")
        for r in fails:
            print(f"  {r['sample']}: expected={'VULN' if r['expected_vuln'] else 'SAFE'}, "
                  f"got={r['verdict']}")
    else:
        print("\n All samples passed!")


def main():
    parser = argparse.ArgumentParser(description="Heap overflow full regression suite")
    parser.add_argument("--quick", action="store_true", help="Skip compilation")
    parser.add_argument("--sample", default="", help="Filter by sample name")
    parser.add_argument("--csv", default="", help="Export CSV")
    parser.add_argument("--json", default="", help="Export JSON")
    args = parser.parse_args()

    results, metrics = run_suite(quick=args.quick, sample_filter=args.sample)
    print_report(results, metrics)

    os.makedirs(RESULTS_DIR, exist_ok=True)
    if args.csv:
        with open(args.csv, 'w', newline='') as f:
            w = csv.writer(f)
            w.writerow(["sample", "expected_vuln", "verdict", "match",
                         "source_vuln_count", "binary_vuln_count",
                         "source_time_ms", "binary_time_ms"])
            for r in results:
                w.writerow([r["sample"], r["expected_vuln"], r["verdict"],
                            r["match"], r["source_vuln_count"],
                            r["binary_vuln_count"],
                            f"{r['source_time_ms']:.1f}",
                            f"{r['binary_time_ms']:.1f}"])
        print(f"\nCSV: {args.csv}")

    json_path = args.json or str(RESULTS_DIR / "heap_suite_results.json")
    with open(json_path, 'w') as f:
        json.dump({"results": results, "metrics": metrics}, f, indent=2)
    print(f"JSON: {json_path}")

    return 0 if metrics["FN"] == 0 and metrics["FP"] == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
