# 结果收集与对比模块 - 批量扫描 + 判定 + CSV/JSON 输出.
# 输出: results/regression_results.csv, results/regression_results.json,
#       results/ablation_summary.json

import csv
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(r"C:\Users\Administrator\Desktop\BinMind\deemo")))

from compile_samples import find_sample_dirs  # noqa: E402
from scan_dispatch import scan_sample  # noqa: E402

_FP_DIR = Path(r"C:\Users\Administrator\Desktop\BinMind\deemo\tests\samples\heap_fp_reduction")
_CVE_DIR = Path(r"C:\Users\Administrator\Desktop\BinMind\deemo\tests\samples\heap_overflow")
_BWR_DIR = ROOT / "samples_bwr"

# 逐样本真值 (vuln/safe). 规则优先级: 显式条目 > 名称推断.
_EXPLICIT_VULN = {
    "bwr_01_strcpy_literal_overflow", "bwr_04_sprintf_literal_overflow",
    "bwr_05_snprintf_argfix", "bwr_07_fread_product", "bwr_08_read_dstfix",
}
_EXPLICIT_SAFE = {
    "bwr_02_strcpy_literal_safe", "bwr_03_strcpy_heap_source_safe",
    "bwr_06_strcpy_stack_source_safe",
    "HEAP-OVERFLOW-FP-04", "HEAP-OVERFLOW-ALIGN-05",
}


def truth_for(name: str):
    if name in _EXPLICIT_VULN:
        return True
    if name in _EXPLICIT_SAFE:
        return False
    if name.startswith("fp_"):
        return False
    if name.startswith("CVE-") or name.startswith("cve_"):
        return True
    if name.startswith("HEAP-OVERFLOW-"):
        return True
    return None


def build_registry() -> list:
    """返回 [(sample_name, dir_path, is_vuln), ...]."""
    reg = []
    for base, mode in ((_BWR_DIR, "scan"), (_FP_DIR, "scan"),
                       (_CVE_DIR, "scan")):
        for d in find_sample_dirs(str(base)):
            truth = truth_for(d.name)
            if truth is None:
                continue
            if not (d / "vuln.exe").exists():
                continue
            reg.append((d.name, str(d / "vuln.exe"), truth))
    return reg


def verdict(is_vuln: bool, count: int) -> str:
    if is_vuln and count > 0:
        return "TP"
    if is_vuln and count == 0:
        return "FN"
    if not is_vuln and count > 0:
        return "FP"
    return "TN"


def collect(output_dir: Path = None):
    output_dir = output_dir or (ROOT / "results")
    output_dir.mkdir(parents=True, exist_ok=True)
    registry = build_registry()
    print(f"[collect] {len(registry)} samples in registry")

    rows = []
    summary = {"enhanced": {"TP": 0, "FP": 0, "FN": 0, "TN": 0,
                            "time_ms": 0.0},
               "baseline": {"TP": 0, "FP": 0, "FN": 0, "TN": 0,
                            "time_ms": 0.0}}

    for name, path, is_vuln in registry:
        try:
            enh = scan_sample(path, enable_bwr=True, enable_pcst=True)
            base = scan_sample(path, enable_bwr=False, enable_pcst=False)
        except Exception as e:
            rows.append({"sample": name, "truth": "vuln" if is_vuln else "safe",
                         "enhanced_verdict": "ERR", "enhanced_count": -1,
                         "enhanced_time_ms": 0.0,
                         "enhanced_bwr_safe": 0, "enhanced_bwr_overflow": 0,
                         "enhanced_raw": 0,
                         "baseline_verdict": "ERR", "baseline_count": -1,
                         "baseline_time_ms": 0.0,
                         "error": f"{type(e).__name__}: {e}"[:120]})
            print(f"  [ERROR] {name}: {type(e).__name__} {e}")
            continue
        ev = verdict(is_vuln, enh["count"])
        bv = verdict(is_vuln, base["count"])
        summary["enhanced"][ev] += 1
        summary["enhanced"]["time_ms"] += enh["time_ms"]
        summary["baseline"][bv] += 1
        summary["baseline"]["time_ms"] += base["time_ms"]
        rows.append({
            "sample": name, "truth": "vuln" if is_vuln else "safe",
            "enhanced_verdict": ev, "enhanced_count": enh["count"],
            "enhanced_time_ms": enh["time_ms"],
            "enhanced_bwr_safe": enh.get("bwr", {}).get("safe_suppressed", 0),
            "enhanced_bwr_overflow": enh.get("bwr", {}).get("overflow", 0),
            "enhanced_raw": enh["raw_count"],
            "baseline_verdict": bv, "baseline_count": base["count"],
            "baseline_time_ms": base["time_ms"],
        })

    for key in ("enhanced", "baseline"):
        s = summary[key]
        tp, fp, fn, tn = s["TP"], s["FP"], s["FN"], s["TN"]
        n = max(tp + fn, 1)
        s["recall"] = round(tp / n * 100, 2)
        s["precision"] = round(tp / max(tp + fp, 1) * 100, 2)
        s["fpr"] = round(fp / max(fp + tn, 1) * 100, 2)
        s["f1"] = round(2 * tp / max(2 * tp + fp + fn, 1), 4)
        s["avg_time_ms"] = round(s["time_ms"] / max(len(registry), 1), 2)

    csv_path = output_dir / "regression_results.csv"
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    with open(output_dir / "regression_results.json", "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "summary": summary}, f, indent=2,
                  ensure_ascii=False)

    with open(output_dir / "ablation_summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print(f"\n==== ENHANCED (BWR+PCST) ====\n{json.dumps(summary['enhanced'], indent=2)}")
    print(f"\n==== BASELINE (legacy) ====\n{json.dumps(summary['baseline'], indent=2)}")
    print(f"\n[csv] {csv_path}")
    return summary


if __name__ == "__main__":
    collect()
