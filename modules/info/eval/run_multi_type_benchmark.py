#!/usr/bin/env python
"""eval/run_multi_type_benchmark.py — 多类型漏洞检测统一benchmark
覆盖: Heap Overflow / UAF / Integer Overflow / Format String / Double Free / Stack Overflow
对每种类型运行对应检测器, 输出 JSON + CSV + 摘要。

用法: python eval/run_multi_type_benchmark.py [--type uaf|int|fmt|heap|all]
"""

import json, time, sys, os
from pathlib import Path
from typing import Dict, List, Tuple

# 将 analysis/ 加入 sys.path — 检测器模块之间的 import 不带 analysis. 前缀
_ANALYSIS_DIR = Path(__file__).parent.parent / "analysis"
if str(_ANALYSIS_DIR) not in sys.path:
    sys.path.insert(0, str(_ANALYSIS_DIR))

_SAMPLES_DIR = Path(__file__).parent.parent / "tests" / "regression" / "samples"
_OUT_JSON = Path(__file__).parent / "multi_type_benchmark.json"
_OUT_CSV = Path(__file__).parent / "multi_type_benchmark.csv"

# 类型→检测器映射
# 每个类型可以有多个检测器, 取 OR 逻辑 (任一检出即算检出)
TYPE_DETECTORS = {
    "heap_overflow": [
        ("heap_overflow_v2", "detect_heap_overflow_v2"),
        ("heap_fp_filter", "analyze_heap_safety"),
    ],
    "uaf": [
        ("uaf_detector_v2", "detect_uaf_v2"),
        ("uaf_lifecycle", "detect_uaf_v3"),
        ("uaf_field_access_tracker", "detect_field_uaf"),
        ("uaf_field_access_tracker", "detect_list_traversal_uaf"),
    ],
    "integer_overflow": [
        ("int_overflow_v3", "detect_int_overflow_v3"),
        ("int_overflow_cross_func", "detect_int_overflow_cross_func"),
    ],
    "format_string": [
        ("format_string_v3", "detect_format_string_v3"),
        ("format_string_deep", "detect_format_string_deep"),
    ],
    "double_free": [
        ("double_free_analyzer", "detect_double_free"),
    ],
    "stack_overflow": [
        ("stack_overflow_v3", "detect_stack_overflow_v3"),
    ],
}

# 样本→漏洞类型映射 (基于目录名关键字)
_TYPE_KEYWORDS = {
    "heap_overflow": ["heap_overflow", "heap", "_heap", "heartbleed", "ghost",
                       "grub_heap", "sudo_heap", "libssh_heap", "proftpd_heap",
                       "kernel_heap", "linux_heap"],
    "uaf": ["_uaf", "_uaf_", "event_uaf"],
    "double_free": ["_df", "double_free", "aliased_df", "conditional_df",
                    "loop_df", "struct_field_df", "array_df", "realloc_df",
                    "interproc_df", "null_check_df", "signal_df",
                    "error_path_df", "list_df", "thread_df", "wrapper_df",
                    "realloc_shrink_df"],
    "integer_overflow": ["int_overflow", "integer_overflow"],
    "format_string": ["_fmt", "format_string"],
    "stack_overflow": ["stack_overflow", "_stack", "pie_stack"],
}


def classify_sample(dirname: str) -> List[str]:
    """根据目录名推断该样本属于哪些漏洞类型。"""
    types = []
    dirname_lower = dirname.lower()
    for vtype, keywords in _TYPE_KEYWORDS.items():
        for kw in keywords:
            if kw in dirname_lower:
                types.append(vtype)
                break
    return types


def load_sample_code(sample_dir: Path) -> str:
    """加载样本的C源码 (UTF-8, 容错)。"""
    for name in ["vuln.c", "main.c", "exploit.c", "test.c"]:
        fpath = sample_dir / name
        if fpath.exists():
            return fpath.read_text(encoding="utf-8", errors="replace")
    # 尝试加载任意 .c 文件
    for cf in sample_dir.glob("*.c"):
        return cf.read_text(encoding="utf-8", errors="replace")
    return ""


def run_detector(mod_name: str, func_name: str, code: str) -> List[Dict]:
    """运行单个检测器, 返回发现列表。
    自动适配两种返回格式: List[Dict] (直接返回) 或 Dict (取 'findings' 键)。
    """
    try:
        mod = __import__(mod_name, fromlist=[func_name])
        fn = getattr(mod, func_name)
        result = fn(code, "")
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            # analyze_heap_safety 返回 {"findings": [...], "stats": {...}}
            findings = result.get("findings", [])
            if isinstance(findings, list):
                return findings
    except Exception as e:
        # 静默失败但记录模块名 — 生产环境应 log.warning
        pass
    return []


def run_type_detectors(vtype: str, code: str) -> List[Dict]:
    """对一种漏洞类型运行所有关联检测器。"""
    all_findings = []
    detectors = TYPE_DETECTORS.get(vtype, [])
    for mod_name, func_name in detectors:
        findings = run_detector(mod_name, func_name, code)
        all_findings.extend(findings)
    return all_findings


def run_benchmark(selected_types: List[str] = None) -> Dict:
    """运行完整benchmark。"""
    if selected_types is None:
        selected_types = list(TYPE_DETECTORS.keys())

    results = {"summary": {}, "details": []}
    samples = sorted(d for d in _SAMPLES_DIR.iterdir()
                     if d.is_dir() and not d.name.startswith("tests"))

    for sample_dir in samples:
        sample_types = classify_sample(sample_dir.name)
        relevant = [t for t in sample_types if t in selected_types]
        if not relevant:
            continue

        code = load_sample_code(sample_dir)
        if not code:
            continue

        for vtype in relevant:
            t0 = time.time()
            findings = run_type_detectors(vtype, code)
            elapsed_ms = round((time.time() - t0) * 1000, 1)

            high_conf = [f for f in findings if f.get("confidence", 0) >= 0.25]
            low_conf = [f for f in findings if 0 < f.get("confidence", 0) < 0.25]
            result = {
                "sample": sample_dir.name,
                "vuln_type": vtype,
                "total_findings": len(findings),
                "high_conf_findings": len(high_conf),
                "elapsed_ms": elapsed_ms,
                "detected": len(high_conf) > 0,
            }
            results["details"].append(result)

    # 汇总统计
    for vtype in selected_types:
        type_results = [r for r in results["details"] if r["vuln_type"] == vtype]
        if not type_results:
            continue
        total = len(type_results)
        detected = sum(1 for r in type_results if r["detected"])
        results["summary"][vtype] = {
            "total_samples": total,
            "detected": detected,
            "detection_rate": round(detected / total * 100, 1) if total > 0 else 0,
            "avg_time_ms": round(sum(r["elapsed_ms"] for r in type_results) / total, 1),
            "avg_findings": round(sum(r["total_findings"] for r in type_results) / total, 1),
        }

    results["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    return results


def save_results(results: Dict):
    """保存 JSON + CSV。"""
    with open(_OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"[bench] JSON: {_OUT_JSON}")

    with open(_OUT_CSV, "w", encoding="utf-8") as f:
        f.write("sample,vuln_type,total_findings,high_conf_findings,elapsed_ms,detected\n")
        for r in results["details"]:
            f.write(f"{r['sample']},{r['vuln_type']},{r['total_findings']},"
                    f"{r['high_conf_findings']},{r['elapsed_ms']},{r['detected']}\n")
    print(f"[bench] CSV: {_OUT_CSV}")


def print_summary(results: Dict):
    """打印人类可读的摘要。"""
    print("\n" + "=" * 70)
    print("  Multi-Type Vulnerability Detection Benchmark")
    print("=" * 70)
    print(f"{'Vuln Type':<22} {'Samples':>8} {'Detected':>8} {'Rate':>8} {'Avg Time':>10}")
    print("-" * 70)
    for vtype, summary in results.get("summary", {}).items():
        print(f"{vtype:<22} {summary['total_samples']:>8} {summary['detected']:>8} "
              f"{summary['detection_rate']:>7.1f}% {summary['avg_time_ms']:>8.1f}ms")
    print("=" * 70)


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--type", default="all",
                       choices=["all", "heap", "uaf", "int", "fmt", "df", "stack"])
    args = parser.parse_args()

    type_map = {
        "all": None, "heap": ["heap_overflow"], "uaf": ["uaf", "double_free"],
        "int": ["integer_overflow"], "fmt": ["format_string"],
        "df": ["double_free"], "stack": ["stack_overflow"],
    }
    selected = type_map.get(args.type)

    results = run_benchmark(selected)
    save_results(results)
    print_summary(results)


if __name__ == "__main__":
    main()
