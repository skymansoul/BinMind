# coding: utf-8
# 自动化回归测试套件 v1
# 统一运行 CVE + FP-safe + SAWCE 三类样本, 输出 TP/FP/TN/FN/Recall/Precision/F1.
# 创建: 2026-05-17
#
# 样本分类:
# CVE: 已知漏洞二进制 → 期望检出(TP), 未检出=FN
#   - FP-safe: 含 _vuln + _safe 双函数 → _safe检出=FP, _vuln未检出=FN
#   - SAWCE: SAWCE针对性样本 → 按manifest的expected_vulnerable判定

import sys, json, time, csv
from pathlib import Path
from typing import List, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.heap_overflow_detect import HeapOverflowDetector
from modules.analysis.static.heap_alloc_model import AllocatorFamily

BENCHMARK_ROOT = PROJECT_ROOT / "modules" / "analysis" / "benchmark"
CVE_DIR = BENCHMARK_ROOT / "samples"
FP_SAFE_DIR = BENCHMARK_ROOT / "samples_heap_safe"
SAWCE_DIR = BENCHMARK_ROOT / "samples_sawce"
RESULTS_DIR = SCRIPT_DIR / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)


def _run_detector(binary_path: str) -> Tuple[list, str, float]:
    """执行BinMind检测器, 返回 (findings, error, time_ms)."""
    t0 = time.perf_counter()
    try:
        ins, fmt, main_addr, ranges = disassemble_binary(binary_path)
        det = HeapOverflowDetector(
            AllocatorFamily.GLIBC,
            use_win64_abi="pei" in fmt.lower())
        if main_addr:
            det.set_min_user_addr(main_addr)
        if ranges:
            det.set_user_func_ranges(ranges)
        det.pre_analyze(ins)
        for i in ins:
            det.analyze_instruction(i)
        findings = det.finalize(ins)
        return findings, "", round((time.perf_counter() - t0) * 1000, 1)
    except Exception as e:
        return [], str(e)[:200], round((time.perf_counter() - t0) * 1000, 1)


def _func_name_from_addr(ins: list, addr: int, ranges: list) -> str:
    """根据地址推断所属函数名."""
    for lo, hi in ranges:
        if lo <= addr < hi:
            for i in ins:
                a = i.get("address", 0)
                if lo <= a < hi:
                    for op in i.get("operands", []):
                        if "<" in op and ">" in op:
                            return op.split("<")[-1].split(">")[0].split("+")[0]
            return f"func_{lo:x}"
    return ""


def test_cve_samples() -> List[dict]:
    """CVE样本召回测试 — 期望全部检出."""
    results = []
    exes = sorted(CVE_DIR.rglob("*.exe"))
    heap_exes = [e for e in exes
                 if "heap" in e.stem.lower()
                 and "doublefree" not in str(e).lower()]
    print(f"\n[1] CVE Samples: {len(heap_exes)} binaries")

    for exe in heap_exes:
        name = exe.stem
        findings, err, ms = _run_detector(str(exe))
        detected = len(findings) > 0
        opt = "O2" if "_O2" in name else ("Os" if "_Os" in name else "O0")
        r = {
            "category": "cve", "name": name,
            "binary": str(exe), "opt": opt,
            "detected": detected,
            "findings_count": len(findings),
            "time_ms": ms, "error": err,
            "expected": "vuln",
            "result": "TP" if detected else "FN",
        }
        results.append(r)
        status = "TP" if detected else "FN!"
        print(f"  {status:4s} {name} ({opt}) {len(findings)}f {ms}ms"
              + (f" ERR:{err}" if err else ""))
    return results


def test_fp_safe_samples() -> List[dict]:
    """FP-safe样本精确率测试 — _safe函数不应检出."""
    manifest_path = FP_SAFE_DIR / "benchmark_fp_safe_manifest.json"
    if not manifest_path.exists():
        print(f"\n[2] FP-safe: manifest not found, skipping")
        return []
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    compiled = [e for e in manifest if e.get("compiled")]
    print(f"\n[2] FP-safe Samples: {len(compiled)} binaries")

    results = []
    for entry in compiled:
        binary = entry.get("binary", "")
        if not binary or not Path(binary).exists():
            continue
        name = entry.get("name", Path(binary).stem)
        opt = entry.get("opt", "?")

        ins, fmt, main_addr, ranges = disassemble_binary(binary)
        det = HeapOverflowDetector(
            AllocatorFamily.GLIBC,
            use_win64_abi="pei" in fmt.lower())
        if main_addr:
            det.set_min_user_addr(main_addr)
        if ranges:
            det.set_user_func_ranges(ranges)
        det.pre_analyze(ins)
        for i in ins:
            det.analyze_instruction(i)
        t0 = time.perf_counter()
        findings = det.finalize(ins)
        ms = round((time.perf_counter() - t0) * 1000, 1)

        safe_fp = 0
        vuln_detected = 0
        for f in findings:
            wa = f.get("write_addr", 0)
            fn = _func_name_from_addr(ins, wa, ranges).lower()
            if "_safe" in fn:
                safe_fp += 1
            elif "_vuln" in fn:
                vuln_detected += 1

        is_fp = safe_fp > 0
        r = {
            "category": "fp_safe", "name": name,
            "binary": binary, "opt": opt,
            "detected": len(findings) > 0,
            "findings_count": len(findings),
            "safe_fp_count": safe_fp,
            "vuln_detected_count": vuln_detected,
            "time_ms": ms, "error": "",
            "expected": "safe_in_safe_func",
            "result": "FP" if is_fp else "TN",
        }
        results.append(r)
        status = "FP!" if is_fp else "TN"
        print(f"  {status:4s} {name} ({opt}) safe_fp={safe_fp} vuln_det={vuln_detected} {ms}ms")
    return results


def test_sawce_samples() -> List[dict]:
    """SAWCE针对性样本测试 — 按manifest判定期望结果."""
    manifest_path = SAWCE_DIR / "sawce_manifest.json"
    if not manifest_path.exists():
        print(f"\n[3] SAWCE: manifest not found, skipping")
        return []
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    compiled = [e for e in manifest if e.get("compiled")]
    print(f"\n[3] SAWCE Samples: {len(compiled)} binaries")

    results = []
    for entry in compiled:
        binary = entry.get("binary", "")
        if not binary or not Path(binary).exists():
            continue
        name = entry.get("name", "")
        opt = entry.get("opt", "?")
        pattern = entry.get("pattern", "")
        expected_vuln = entry.get("expected_vulnerable", False)
        challenge = entry.get("challenge", "")

        findings, err, ms = _run_detector(binary)
        detected = len(findings) > 0

        if expected_vuln:
            result = "TP" if detected else "FN"
        else:
            result = "FP" if detected else "TN"

        r = {
            "category": "sawce", "name": name,
            "binary": binary, "opt": opt,
            "pattern": pattern,
            "detected": detected,
            "findings_count": len(findings),
            "time_ms": ms, "error": err,
            "expected_vuln": expected_vuln,
            "challenge": challenge,
            "result": result,
        }
        results.append(r)
        print(f"  {result:4s} {name}_{opt} [{pattern}] {len(findings)}f {ms}ms"
              + (f" ERR:{err}" if err else ""))
    return results


def compute_metrics(cve_r, fp_r, sawce_r):
    """统一计算 TP/FP/TN/FN/Recall/Precision/F1."""
    tp = sum(1 for r in cve_r if r["result"] == "TP")
    fn = sum(1 for r in cve_r if r["result"] == "FN")
    tp += sum(1 for r in sawce_r if r["result"] == "TP")
    fn += sum(1 for r in sawce_r if r["result"] == "FN")

    fp = sum(1 for r in fp_r if r["result"] == "FP")
    tn = sum(1 for r in fp_r if r["result"] == "TN")
    fp += sum(1 for r in sawce_r if r["result"] == "FP")
    tn += sum(1 for r in sawce_r if r["result"] == "TN")

    recall = tp / max(tp + fn, 1)
    precision = tp / max(tp + fp, 1)
    f1 = 2 * recall * precision / max(recall + precision, 1e-9)
    fpr = fp / max(fp + tn, 1)

    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "recall": round(recall, 4),
        "precision": round(precision, 4),
        "fpr": round(fpr, 4),
        "f1": round(f1, 4),
        "cve_count": len(cve_r),
        "fp_safe_count": len(fp_r),
        "sawce_count": len(sawce_r),
    }


def main():
    print("=" * 70)
    print("BinMind Regression Test Suite — Heap Overflow Detection")
    print("=" * 70)

    cve_results = test_cve_samples()
    fp_results = test_fp_safe_samples()
    sawce_results = test_sawce_samples()

    all_results = cve_results + fp_results + sawce_results
    metrics = compute_metrics(cve_results, fp_results, sawce_results)

    out_json = RESULTS_DIR / "regression_results.json"
    out_json.write_text(json.dumps({
        "tool": "BinMind",
        "version": "v3.2 + SAWCE (Stage 9/10)",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "metrics": metrics,
        "results": all_results,
    }, indent=2, default=str, ensure_ascii=False))

    out_csv = RESULTS_DIR / "regression_results.csv"
    with open(out_csv, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=[
            "category", "name", "opt", "pattern", "detected",
            "findings_count", "safe_fp_count", "expected_vuln",
            "result", "time_ms", "error"],
            extrasaction="ignore")
        w.writeheader()
        w.writerows(all_results)

    print(f"\n{'=' * 70}")
    print(f"Regression Test Summary")
    print(f"{'=' * 70}")
    print(f"  CVE samples:     {metrics['cve_count']}")
    print(f"  FP-safe samples: {metrics['fp_safe_count']}")
    print(f"  SAWCE samples:   {metrics['sawce_count']}")
    print(f"  TP={metrics['tp']}  FP={metrics['fp']}  "
          f"TN={metrics['tn']}  FN={metrics['fn']}")
    print(f"  Recall:    {metrics['recall']:.4f} "
          f"({metrics['recall']*100:.1f}%)")
    print(f"  Precision: {metrics['precision']:.4f} "
          f"({metrics['precision']*100:.1f}%)")
    print(f"  FPR:       {metrics['fpr']:.4f} "
          f"({metrics['fpr']*100:.1f}%)")
    print(f"  F1 Score:  {metrics['f1']:.4f}")
    print(f"\n  JSON: {out_json}")
    print(f"  CSV:  {out_csv}")

    return metrics


if __name__ == "__main__":
    main()
