# UAF多工具对比实验 v1 — BinMind vs Angr vs Ghidra vs QEMU
#
# 对15个CVE UAF样本 + 20个FP-safe样本执行四工具对比
# 输出 Precision/Recall/FPR/F1/时间 对比表
#
# 创建: 2026-06-24

import sys, json, time, argparse
from pathlib import Path
from typing import Dict, List

BASE = Path(__file__).resolve().parents[1]
EVAL_DIR = Path(__file__).resolve().parent
RESULTS_DIR = EVAL_DIR / "results_uaf"
RESULTS_DIR.mkdir(exist_ok=True)
BUILD_TMP = EVAL_DIR / "build_tmp_uaf"
BUILD_TMP.mkdir(exist_ok=True)

_PROJECT_ROOT = BASE.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

CVE_SAMPLES_DIR = BASE / "benchmark" / "samples_uaf"
FP_SAFE_DIR = BASE / "benchmark" / "samples_uaf_safe"


def run_binmind(binary_path: str) -> dict:
    from batch_test_uaf import run_uaf_detection
    return run_uaf_detection(binary_path)


def run_angr(binary_path: str) -> dict:
    try:
        from angr_uaf_baseline import analyze_binary
        return analyze_binary(binary_path, timeout=60)
    except Exception as e:
        return {"tool": "Angr-UAF", "detected": False, "finding_count": 0,
                "time_ms": 0, "error": str(e)[:200]}


def run_ghidra(binary_path: str) -> dict:
    try:
        from ghidra_uaf_baseline import analyze_binary
        return analyze_binary(binary_path, timeout=60)
    except Exception as e:
        return {"tool": "Ghidra-UAF", "detected": False, "finding_count": 0,
                "time_ms": 0, "error": str(e)[:200]}


def run_qemu(binary_path: str) -> dict:
    try:
        from qemu_uaf_baseline import analyze_binary
        return analyze_binary(binary_path, timeout=10)
    except Exception as e:
        return {"tool": "QEMU-UAF", "detected": False, "finding_count": 0,
                "time_ms": 0, "error": str(e)[:200]}


TOOLS = {
    "BinMind-PDL": run_binmind,
    "Angr": run_angr,
    "Ghidra": run_ghidra,
    "QEMU": run_qemu,
}


def load_cve_samples() -> List[dict]:
    """加载CVE样本: 优先用batch_test_uaf编译的O0二进制."""
    entries = []
    for cve_dir in sorted(CVE_SAMPLES_DIR.iterdir()):
        if not cve_dir.is_dir():
            continue
        cve_name = cve_dir.name
        # 优先用 build_tmp_uaf 中 batch_test 编译的版本
        batch_binary = BUILD_TMP / f"{cve_name}_O0.exe"
        if batch_binary.exists():
            entries.append({
                "name": cve_name, "binary": str(batch_binary),
                "expected": "vuln", "category": "cve"})
            continue
        # fallback: 用目录中已有的 O0 exe
        for exe in sorted(cve_dir.glob("*O0.exe")):
            entries.append({
                "name": cve_name, "binary": str(exe),
                "expected": "vuln", "category": "cve"})
    return entries


def load_fp_safe_samples() -> List[dict]:
    entries = []
    manifest_path = FP_SAFE_DIR / "manifest.json"
    if not manifest_path.exists():
        return entries
    with open(manifest_path) as f:
        manifest = json.load(f)
    for entry in manifest:
        if entry.get("opt") != "O0":
            continue
        if not Path(entry["binary"]).exists():
            continue
        entries.append({
            "name": f"{entry['pattern']}_{entry['variant']}",
            "binary": entry["binary"],
            "expected": entry.get("expected", "unknown"),
            "category": "fp_safe", "variant": entry["variant"]})
    return entries


def compute_metrics(results: List[dict], expected: str) -> dict:
    tp = sum(1 for r in results if r.get("detected") and expected == "vuln")
    fp = sum(1 for r in results if r.get("detected") and expected == "safe")
    tn = sum(1 for r in results if not r.get("detected") and expected == "safe")
    fn = sum(1 for r in results if not r.get("detected") and expected == "vuln")
    prec = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    fpr = fp / max(1, fp + tn) if (fp + tn) > 0 else 0.0
    f1 = 2 * prec * recall / max(1, prec + recall)
    avg_time = sum(r.get("time_ms", 0) for r in results) / max(1, len(results))
    return {"TP": tp, "FP": fp, "TN": tn, "FN": fn,
            "precision": prec, "recall": recall, "fpr": fpr,
            "f1": f1, "avg_time_ms": round(avg_time, 1)}


if __name__ == "__main__":
    all_samples = load_cve_samples() + load_fp_safe_samples()
    print(f"Loaded {len(all_samples)} samples "
          f"({len(load_cve_samples())} CVE + {len(load_fp_safe_samples())} FP-safe)")

    all_results: Dict[str, List[dict]] = {t: [] for t in TOOLS}

    for i, sample in enumerate(all_samples):
        print(f"\n[{i+1}/{len(all_samples)}] {sample['name']} "
              f"({sample['category']}/{sample['expected']})")
        for tool_name, tool_fn in TOOLS.items():
            r = tool_fn(sample["binary"])
            r["sample"] = sample["name"]
            r["expected"] = sample["expected"]
            r["category"] = sample["category"]
            all_results[tool_name].append(r)
            status = "DETECT" if r.get("detected") else "CLEAN"
            err = f" ERR:{r['error'][:30]}" if r.get("error") else ""
            print(f"  {tool_name:15s}: {status} "
                  f"{r.get('finding_count', 0)}f {r.get('time_ms', 0):.0f}ms{err}")

    print(f"\n{'='*80}")
    print("UAF Multi-Tool Comparison Report")
    print(f"{'='*80}")

    vuln_samples = load_cve_samples()
    safe_samples = load_fp_safe_samples()
    n_vuln = len(vuln_samples)
    n_safe = len(safe_samples)

    print(f"\nCVE Samples (vuln): {n_vuln} | FP-safe Samples (safe): {n_safe}")
    print(f"\n{'Tool':<15} {'TP':>3} {'FP':>3} {'TN':>3} {'FN':>3} "
          f"{'P':>7} {'R':>7} {'FPR':>7} {'F1':>7} {'Avg(ms)':>8}")
    print("-" * 75)

    for tool_name in TOOLS:
        results = all_results[tool_name]
        vuln_results = [r for r in results if r["expected"] == "vuln"]
        safe_results = [r for r in results if r["expected"] == "safe"]
        m_v = compute_metrics(vuln_results, "vuln")
        m_s = compute_metrics(safe_results, "safe")
        tp = m_v["TP"]; fn = m_v["FN"]
        fp = m_s["FP"]; tn = m_s["TN"]
        prec = tp / max(1, tp + fp)
        recall = tp / max(1, tp + fn)
        fpr = fp / max(1, fp + tn) if (fp + tn) > 0 else 0.0
        f1 = 2 * prec * recall / max(1, prec + recall)
        avg_time = sum(r.get("time_ms", 0) for r in results) / max(1, len(results))
        print(f"{tool_name:<15} {tp:3d} {fp:3d} {tn:3d} {fn:3d} "
              f"{prec:6.1%} {recall:6.1%} {fpr:6.1%} {f1:6.4f} {avg_time:7.1f}")

    report = {"tools": {}}
    for tool_name in TOOLS:
        report["tools"][tool_name] = all_results[tool_name]
    out_path = RESULTS_DIR / "uaf_multi_tool_comparison.json"
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\nResults saved to {out_path}")
