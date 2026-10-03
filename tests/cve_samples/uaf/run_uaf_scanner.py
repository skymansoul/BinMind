"""
UAF样本扫描器 — 对15个UAF基准样本运行四阶段级联管线, 收集检测结果.

用法: python tests/cve_samples/uaf/run_uaf_scanner.py
输出: tests/cve_samples/uaf/scan_results/scan_output.json

管线: 提取候选 → Phase0(模式安全) → Phase1(别名生命周期) → Phase2(路径支配) → Phase3(逃逸分析)
"""

import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

# 确保 deemo 根目录在 Python 路径中 (从 tests/cve_samples/uaf/ 向上四级)
_DEEMO_ROOT = Path(__file__).parent.parent.parent.parent
if str(_DEEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(_DEEMO_ROOT))

SAMPLE_DIR = Path(__file__).parent
RESULTS_DIR = SAMPLE_DIR / "scan_results"


def load_truth(sample_dir: Path) -> Optional[Dict]:
    """加载样本的 ground truth."""
    tf = sample_dir / "truth.json"
    if tf.exists():
        with open(tf, encoding='utf-8') as f:
            return json.load(f)
    return None


def find_c_files(sample_dir: Path) -> List[Path]:
    """在样本目录中找所有 .c 源文件."""
    return sorted(sample_dir.glob("*.c"))


def scan_sample(sample_dir: Path) -> Dict[str, Any]:
    """扫描单个样本目录: 读取C源码, 运行UAF级联管线."""
    result: Dict[str, Any] = {
        "sample": sample_dir.name,
        "files_scanned": [],
        "candidates": [],    # 确认为 UAF 的候选
        "uncertain": [],     # UNCERTAIN 判定的候选 (保守保留)
        "filtered": [],      # 被级联过滤的候选 (可证明安全)
        "scan_time_ms": 0,
        "error": None,
    }

    c_files = find_c_files(sample_dir)
    if not c_files:
        result["error"] = "No C source files found"
        return result

    t0 = time.time()
    all_candidates = []
    all_filtered = []

    try:
        from analysis.uaf_fp_cascade import run_uaf_cascade, UafVerdict

        for cf in c_files:
            source = cf.read_text(encoding='utf-8', errors='replace')
            func_name = cf.stem
            candidates, report = run_uaf_cascade(source, func_name)

            result["files_scanned"].append(cf.name)
            # 从级联报告提取各阶段过滤数
            result["phase0_filtered"] = report.phase0_filtered
            result["phase1_filtered"] = report.phase1_filtered
            result["phase2_filtered"] = report.phase2_filtered

            for c in candidates:
                entry = {
                    "ptr_name": c.ptr_name,
                    "func": c.func_name,
                    "alloc_lineno": c.alloc_lineno,
                    "free_lineno": c.free_lineno,
                    "use_lineno": c.use_lineno,
                    "confidence": round(c.confidence, 3),
                    "verdict": c.verdict.value,
                    "reason": c.verdict_reason[:200],
                    "escape": c.escape_level.name,
                    "phases": c.phases_passed,
                }
                if c.verdict in (UafVerdict.LIKELY_TP, UafVerdict.CONFIRMED):
                    all_candidates.append(entry)
                elif c.verdict == UafVerdict.UNCERTAIN:
                    result["uncertain"].append(entry)
                else:
                    all_filtered.append(entry)

    except Exception as e:
        result["error"] = str(e)[:200]

    result["candidates"] = all_candidates
    result["filtered"] = all_filtered
    result["scan_time_ms"] = (time.time() - t0) * 1000
    return result


def classify_result(result: Dict, truth: Optional[Dict]) -> str:
    """将扫描结果分类为 TP/TN/FP/FN.

    保守策略: UNCERTAIN 判定的候选算"检测到", 仅 SAFE/LIKELY_FP 才过滤.
    这保证零新增漏报 — 仅过滤可证明安全的候选.

    Args:
        result: 扫描结果
        truth: ground truth (含 expected 字段: "TP" 或 "TN")

    Returns:
        "TP", "TN", "FP", 或 "FN"
    """
    if not truth:
        return "UNKNOWN"

    expected = truth.get("expected", "")
    # 保守: UNCERTAIN 也算检测到 (不过滤)
    has_findings = (
        len(result.get("candidates", [])) > 0 or
        len(result.get("uncertain", [])) > 0
    )

    if expected == "TP":
        return "TP" if has_findings else "FN"
    elif expected == "TN":
        return "TN" if not has_findings else "FP"
    return "UNKNOWN"


def main():
    os.makedirs(RESULTS_DIR, exist_ok=True)

    # 找所有样本目录
    sample_dirs = sorted(
        d for d in SAMPLE_DIR.iterdir()
        if d.is_dir() and d.name.startswith("uaf_")
    )

    if not sample_dirs:
        print("No UAF sample directories found.")
        return 1

    print(f"Scanning {len(sample_dirs)} UAF benchmark samples...\n")
    all_results = []

    tp_count = tn_count = fp_count = fn_count = 0
    total_candidates_found = 0
    total_uncertain = 0
    total_filtered = 0

    for sd in sample_dirs:
        truth = load_truth(sd)
        expected = truth.get("expected", "?") if truth else "?"

        print(f"  [{expected}] {sd.name}...", end=" ")

        r = scan_sample(sd)
        r["truth"] = truth
        cls = classify_result(r, truth)
        r["classification"] = cls

        n_found = len(r["candidates"])
        n_uncertain = len(r["uncertain"])
        n_filtered = (r.get("phase0_filtered", 0) + r.get("phase1_filtered", 0)
                      + r.get("phase2_filtered", 0))
        total_candidates_found += n_found
        total_uncertain += n_uncertain
        total_filtered += n_filtered

        if cls == "TP":
            tp_count += 1
        elif cls == "TN":
            tn_count += 1
        elif cls == "FP":
            fp_count += 1
        elif cls == "FN":
            fn_count += 1

        status = f"{cls}: {n_found} found, {n_uncertain} uncertain, {n_filtered} filtered"
        if r.get("error"):
            status += f" [ERROR: {r['error'][:40]}]"
        print(f"{status} ({r['scan_time_ms']:.1f}ms)")

        all_results.append(r)

    # 计算指标
    total = tp_count + tn_count + fp_count + fn_count
    precision = tp_count / max(1, tp_count + fp_count) * 100
    recall = tp_count / max(1, tp_count + fn_count) * 100
    f1 = 2 * precision * recall / max(1, precision + recall)
    fp_rate = fp_count / max(1, fp_count + tn_count) * 100

    print(f"\n{'='*60}")
    print(f"UAF Benchmark Results ({total} samples)")
    print(f"{'='*60}")
    print(f"  TP={tp_count}, TN={tn_count}, FP={fp_count}, FN={fn_count}")
    print(f"  Precision:  {precision:.1f}%")
    print(f"  Recall:     {recall:.1f}%")
    print(f"  F1 Score:   {f1:.1f}")
    print(f"  FP Rate:    {fp_rate:.1f}%")
    print(f"  Candidates: {total_candidates_found} confirmed, "
          f"{total_uncertain} uncertain, {total_filtered} filtered")

    # 写输出
    output = {
        "benchmark": "UAF-15 (TARP-E cascade)",
        "total_samples": total,
        "tp": tp_count,
        "tn": tn_count,
        "fp": fp_count,
        "fn": fn_count,
        "precision_pct": round(precision, 1),
        "recall_pct": round(recall, 1),
        "f1_score": round(f1, 1),
        "fp_rate_pct": round(fp_rate, 1),
        "candidates_confirmed": total_candidates_found,
        "candidates_filtered": total_filtered,
        "results": all_results,
    }

    out_file = RESULTS_DIR / "scan_output.json"
    with open(out_file, "w", encoding='utf-8') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"\nScan results → {out_file}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
