"""
SFOD CJ自主率消融 — 量化SFOD桥接对CJ管线(不含HOSV)自主率的提升.

核心思路: 只用CJ管线判定, 不调用HOSV源级验证器.
对比:
  A: CJ-only (无SFOD) — CJ管线无法处理struct field → INCONCLUSIVE
  B: CJ+SFOD (有SFOD) — CJ管线自主处理struct field → SAFE/OVERFLOW

测试对象: cve_51~cve_54(旧struct field样本) + cve_56~cve_60(SFOD挑战样本)
"""
from __future__ import annotations
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Tuple

_DEEMO_ROOT = Path(__file__).resolve().parent.parent
if str(_DEEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(_DEEMO_ROOT))

SAMPLE_DIR = _DEEMO_ROOT / "tests" / "cve_samples" / "heap_overflow"
GROUND_TRUTH_PATH = SAMPLE_DIR / "ground_truth.json"
RESULTS_DIR = _DEEMO_ROOT / "eval" / "results"

# 只测试struct field相关样本
SFOD_SAMPLES = [
    "cve_51_struct_field_offset_safe",
    "cve_52_struct_field_offset_overflow",
    "cve_53_struct_field_safe",
    "cve_54_struct_field_overflow",
    "cve_56_sfod_field_safe",
    "cve_57_sfod_field_overflow",
    "cve_58_sfod_cast_safe",
    "cve_59_sfod_cast_overflow",
    "cve_60_sfod_nested_safe",
]


def run_cj_pipeline(source: str, enable_sfod: bool) -> Dict:
    """运行CJ管线(不含HOSV), 返回判定结果."""
    from core.ir_normalizer import normalize_ir
    from core.heap_overflow_detector import (
        extract_heap_allocations, track_heap_stores,
        HeapOverflowCandidate,
    )
    from core.cj_solver import solve_candidate
    from core.cj_constraint_types import SolverVerdict

    ir_lines = normalize_ir(source)
    allocs = extract_heap_allocations(ir_lines)
    if not allocs:
        return {"verdict": "NO_CANDIDATE", "details": "no allocs found"}

    results = []
    for alloc in allocs:
        stores = track_heap_stores(ir_lines, alloc)
        for store in stores:
            cand = HeapOverflowCandidate(
                alloc_site=alloc, overflow_store=store,
            )
            try:
                result, _ = solve_candidate(
                    cand, ir_lines, source, "x86_64")
                results.append(result)
            except Exception as e:
                results.append(None)

    # 汇总判定
    for r in results:
        if r is None:
            continue
        if r.verdict == SolverVerdict.PROVEN_OVERFLOW:
            return {"verdict": "OVERFLOW", "cj_verdict": str(r.verdict.value)}
        if r.verdict == SolverVerdict.PROVEN_SAFE:
            return {"verdict": "SAFE", "cj_verdict": str(r.verdict.value)}

    if any(r is not None for r in results):
        return {"verdict": "INCONCLUSIVE", "cj_verdict": "INCONCLUSIVE"}

    return {"verdict": "NO_CANDIDATE", "details": "no candidates"}


def run_ablation():
    with open(str(GROUND_TRUTH_PATH), encoding='utf-8') as f:
        gt = json.load(f)

    print("=" * 60)
    print(" SFOD CJ Autonomy Ablation (9 struct field samples)")
    print("=" * 60)

    for config_name, enable_sfod in [("CJ-only (no SFOD)", False),
                                      ("CJ+SFOD", True)]:
        # Monkey-patch
        import core.cj_struct_field as sfod_mod
        _original = sfod_mod.inject_sfod_constraints
        if not enable_sfod:
            sfod_mod.inject_sfod_constraints = lambda *a, **kw: False

        print(f"\n[{config_name}]")
        tp, fp, tn, fn, inc = 0, 0, 0, 0, 0

        for sample_name in SFOD_SAMPLES:
            sample_dir = SAMPLE_DIR / sample_name
            c_files = list(sample_dir.glob("*.c"))
            if not c_files:
                print(f"  {sample_name}: NO .c FILE")
                continue

            source = c_files[0].read_text(encoding='utf-8', errors='replace')
            expected_vuln = gt["samples"].get(sample_name, {}).get(
                "expected_vuln", None)

            result = run_cj_pipeline(source, enable_sfod)
            verdict = result["verdict"]

            if verdict == "NO_CANDIDATE":
                status = "NO_CAND"
            elif verdict == "INCONCLUSIVE":
                inc += 1
                status = "INC"
            elif verdict == "OVERFLOW":
                if expected_vuln:
                    tp += 1
                    status = "TP"
                else:
                    fp += 1
                    status = "FP"
            else:  # SAFE
                if not expected_vuln:
                    tn += 1
                    status = "TN"
                else:
                    fn += 1
                    status = "FN"

            print(f"  {sample_name}: {verdict} ({status})")

        total = tp + fp + tn + fn + inc
        p = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        r = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0.0
        autonomy = (tp + fp + tn + fn) / total if total > 0 else 0.0

        print(f"\n  TP={tp} FP={fp} TN={tn} FN={fn} INC={inc}")
        print(f"  P={p:.4f} R={r:.4f} F1={f1:.4f}")
        print(f"  CJ Autonomy={autonomy:.4f} (INCONCLUSIVE rate={1-autonomy:.4f})")

        # 恢复
        if not enable_sfod:
            sfod_mod.inject_sfod_constraints = _original

    # 保存结果
    out = {
        "experiment": "SFOD CJ Autonomy Ablation",
        "samples": SFOD_SAMPLES,
        "note": "SFOD bridges struct field offsets into CJ constraint system, "
                "enabling CJ to autonomously handle struct field scenarios "
                "without HOSV bypass.",
    }
    out_path = RESULTS_DIR / "sfod_cj_autonomy_ablation.json"
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(str(out_path), "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print(f"\nSaved to: {out_path}")


if __name__ == "__main__":
    run_ablation()
