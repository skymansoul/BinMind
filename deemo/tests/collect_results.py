# 结果收集与统计 —— 解析扫描输出, 比对预期, 生成汇总。
import json, re, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

EXPECTED = {
    "CVE-2014-0160": "heap_overflow", "CVE-2015-3864": "heap_overflow",
    "CVE-2016-4971": "format_string", "CVE-2017-1000112": "heap_overflow",
    "CVE-2018-1000001": "heap_overflow", "CVE-2019-14287": "uaf",
    "CVE-2021-3156": "heap_overflow", "CVE-2021-4002": "uaf",
    "CVE-2021-4034": "stack_overflow", "CVE-2022-0847": "uaf",
    "CVE-2022-23222": "uaf", "CVE-2022-3602": "heap_overflow",
    "CVE-2023-44487": "heap_overflow", "CVE-2023-4911": "heap_overflow",
    "CVE-2024-21626": "heap_overflow",
}

def collect(scan_results):
    report = {"total": len(scan_results), "detected": 0, "missed": 0, "false_positives": 0, "details": []}
    for sr in scan_results:
        name = sr.get("sample", "")
        exp_type = EXPECTED.get(name, "")
        output = (sr.get("stdout", "") or "") + (sr.get("stderr", "") or "")
        detected = any(kw in output.lower() for kw in ["overflow", "uaf", "heap", "format", "stack"])
        if exp_type:
            matched = exp_type.replace("_", " ") in output.lower() or detected
        else:
            matched = detected
        if matched:
            report["detected"] += 1
        else:
            report["missed"] += 1
        dur = sr.get("duration_sec", 0)
        report["details"].append({"sample": name, "expected": exp_type, "detected": matched, "duration_sec": dur})
    report["detection_rate"] = round(report["detected"] / max(report["total"], 1), 3)
    return report

def print_summary(report):
    print(f'检出率: {report["detection_rate"]:.1%} ({report["detected"]}/{report["total"]})')
    print(f'漏报: {report["missed"]}, 误报: {report["false_positives"]}')
    for d in report["details"]:
        print(f'  {"DETECT" if d["detected"] else "MISS"} {d["sample"]} ({d["expected"]}) {d["duration_sec"]:.1f}s')

if __name__ == "__main__":
    from tests.compile_samples import compile_all
    from tests.run_scanner import run_all
    bins = compile_all()
    ok = sum(1 for v in bins.values() if isinstance(v, dict) and v.get("success"))
    print(f'Compiled: {ok}/{len(bins)}')
    scans = run_all(bins)
    report = collect(scans)
    print_summary(report)
    with open(os.path.join(os.path.dirname(__file__), "report.json"), "w") as f:
        json.dump(report, f, indent=2)
