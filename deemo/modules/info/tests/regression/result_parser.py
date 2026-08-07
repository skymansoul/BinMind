# Created: 2026-05-27 11:15:00
# result_parser — 扫描结果解析与统计模块
# 输入: scan_results/*.json + 各样本的 README.md (含预期检测结果)
# 输出: 检出率/漏报率/误报率统计表 + per-sample 明细

import json, os, re
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple

RESULTS_DIR = Path(__file__).parent / "scan_results"
SAMPLES_DIR = Path(__file__).parent / "samples"

# 各 CVE 样本的预期检测类型
_EXPECTED_TYPES: Dict[str, List[str]] = {
    "CVE-2014-0160_heartbleed": ["heap_overflow"],
    "CVE-2015-0235_ghost": ["heap_overflow"],
    "CVE-2016-10190_heap_overflow": ["heap_overflow"],
    "CVE-2017-1000253_pie_stack": ["stack_overflow"],
    "CVE-2019-15922_uaf": ["use_after_free"],
    "CVE-2019-11477_integer_overflow": ["heap_overflow"],
    "CVE-2008-0062_double_free": ["double_free"],
    "CVE-2012-0809_format_string": ["format_string"],
    "CVE-2021-3156_sudo_heap": ["heap_overflow"],
    "CVE-2023-33476_heap_overflow": ["heap_overflow"],
}


def _check_detection(scan: dict, expected_types: List[str]) -> Tuple[bool, bool, str]:
    """判断检出/漏报/误报。返回 (detected, false_positive, detail)。"""
    result = scan.get("result")
    if result is None:
        return (False, False, "scan_error")

    t3 = result.get("tier3_findings", [])
    detected_types = {
        f.get("vuln_type") for f in t3
        if f.get("confidence", 0) >= 0.30
    }
    # 若任何期望类型被检出 → 检出
    detected = any(et in detected_types for et in expected_types)
    # 若检出了非期望的类型 → 可能的误报(对non-target类型而言)
    false_positive_types = detected_types - set(expected_types)

    detail = f"expected={expected_types}, detected={list(detected_types)}"
    if false_positive_types:
        detail += f", FP_types={list(false_positive_types)}"
    return (detected, len(false_positive_types) > 0, detail)


def parse_latest() -> dict:
    """解析最新的扫描结果, 生成统计报告。"""
    json_files = sorted(RESULTS_DIR.glob("scan_*.json"), reverse=True)
    if not json_files:
        return {"error": "no_scan_results_found", "hint": "run scan_runner.py first"}
    latest = json_files[0]

    with open(latest) as f:
        data = json.load(f)

    scans = data.get("scans", [])
    stats = {"total_scans": len(scans), "true_positives": 0, "false_negatives": 0,
             "false_positives": 0, "errors": 0, "per_sample": [], "by_tier": {}}

    # 按样本分组
    by_sample: Dict[str, list] = {}
    for s in scans:
        sn = s.get("sample_name", "unknown")
        by_sample.setdefault(sn, []).append(s)

    for sample_name, sample_scans in sorted(by_sample.items()):
        expected = _EXPECTED_TYPES.get(sample_name, [])
        best_detected = False
        best_conf = 0.0
        best_detail = ""
        has_error = False

        for scan in sample_scans:
            detected, fp, detail = _check_detection(scan, expected)
            if scan.get("error"):
                has_error = True
                continue
            if detected:
                best_detected = True
            # 取最高置信度
            t3 = scan.get("result", {}).get("tier3_findings", [])
            for f in t3:
                if f.get("confidence", 0) > best_conf:
                    best_conf = f["confidence"]
                    best_detail = detail

        entry = {"sample": sample_name, "expected": expected,
                 "detected": best_detected, "max_confidence": round(best_conf, 3),
                 "detail": best_detail, "error": has_error}

        if best_detected:
            stats["true_positives"] += 1
        elif has_error:
            stats["errors"] += 1
        else:
            stats["false_negatives"] += 1
        stats["per_sample"].append(entry)

    total = max(len(stats["per_sample"]), 1)
    stats["detection_rate"] = round(stats["true_positives"] / total, 3)
    stats["false_negative_rate"] = round(stats["false_negatives"] / total, 3)
    stats["error_rate"] = round(stats["errors"] / total, 3)

    # 按 Tier 统计
    for tier_name in ["tier1", "tier2", "tier3"]:
        detected_count = 0
        for sample_name, sample_scans in by_sample.items():
            expected = _EXPECTED_TYPES.get(sample_name, [])
            for scan in sample_scans:
                result = scan.get("result")
                if not result: continue
                findings = result.get(f"{tier_name}_findings", [])
                detected_types = {f.get("vuln_type") for f in findings if f.get("confidence", 0) >= 0.30}
                if any(et in detected_types for et in expected):
                    detected_count += 1
                    break
        stats["by_tier"][tier_name] = {
            "detected": detected_count,
            "total": total,
            "rate": round(detected_count / total, 3),
        }

    stats["source_file"] = str(latest)
    return stats


def print_report(stats: dict) -> None:
    print(f"\n=== CAIR Regression Test Report ===")
    print(f"Scans analyzed: {stats['total_scans']}")
    print(f"Detection rate: {stats['detection_rate']:.1%}")
    print(f"False negative rate: {stats['false_negative_rate']:.1%}")
    print(f"Error rate: {stats['error_rate']:.1%}")
    print(f"\nBy Tier:")
    for t, d in stats.get("by_tier", {}).items():
        print(f"  {t}: {d['detected']}/{d['total']} ({d['rate']:.1%})")
    print(f"\nPer-sample:")
    for e in stats.get("per_sample", []):
        tag = "DETECT" if e["detected"] else ("ERROR" if e["error"] else "MISS")
        print(f"  [{tag}] {e['sample']}: {e['detail']}")


if __name__ == "__main__":
    print_report(parse_latest())
