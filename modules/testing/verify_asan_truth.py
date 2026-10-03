"""ASan 运行时 ground truth 交叉验证脚本 — 校验样本标签真实性."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "eval"))
from qemu_tracer import asan_ground_truth  # noqa: E402

BASE = os.path.dirname(os.path.abspath(__file__))
labels = json.load(open(os.path.join(BASE, "sample_labels.json"),
                        encoding="utf-8"))
vuln = ["cve_unbounded_strcpy_003", "cve_size_mismatch_memcpy_002",
        "cve_loop_bound_error_006", "cve_2018_1121_procps",
        "cve_2018_10732_libmobi", "cve_2021_35942_elfutils",
        "cve_2019_18604_gnuplot", "cve_2017_17506_gdkpixbuf"]
benign = ["tn_01_memcpy_exact", "tn_03_loop_bounded", "tn_05_strcpy_literal",
          "tn_06_multialloc_provenance", "tn_12_realloc_grow",
          "tn_04_nested_loop_bounded"]

print("=== 漏洞样本 (期望: 运行时堆错误) ===")
for n in vuln:
    exe = os.path.join(BASE, "heap_samples", n, "vuln.exe")
    r = asan_ground_truth(exe, n)
    errs = [f["subtype"] for f in r["findings"]]
    print(f"  {n:<30s} {errs if errs else '(无触发)'}")

print("=== 良性样本 (期望: 无运行时错误) ===")
for n in benign:
    exe = os.path.join(BASE, "heap_benign_samples", n, "vuln.exe")
    r = asan_ground_truth(exe, n)
    errs = [f["subtype"] for f in r["findings"]]
    print(f"  {n:<30s} {errs if errs else '(无触发)'}")

report = {"vuln": {}, "benign": {}}
for n in vuln:
    r = asan_ground_truth(os.path.join(BASE, "heap_samples", n, "vuln.exe"),
                          n)
    report["vuln"][n] = [f["subtype"] for f in r["findings"]]
for n in benign:
    r = asan_ground_truth(
        os.path.join(BASE, "heap_benign_samples", n, "vuln.exe"), n)
    report["benign"][n] = [f["subtype"] for f in r["findings"]]
out_path = os.path.join(BASE, "regression_results", "runtime_truth.json")
os.makedirs(os.path.dirname(out_path), exist_ok=True)
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2, ensure_ascii=False)
print(f"\n[OK] 运行时事实源已保存: {out_path}")
