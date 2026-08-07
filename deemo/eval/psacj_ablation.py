#!/usr/bin/env python3
# #[DEPRECATED] 2026-08-08: 此脚本使用 IR 级 detect_heap_overflow 但传入 C 源码文本行,
# 导致检测结果 R=0.05, 与实际回归测试 R=1.0 完全不符. 数据不可信.
# 替代脚本: eval/hosv_ablation.py (基于 HOSV 源级验证器, 与 run_heap_suite.py 对齐).
"""
PSACJ消融实验 — 量化仿射关系证明对FM消元的增量贡献.

#[DEPRECATED] 本脚本数据不可信: 使用 IR 级检测器但传入源码文本, 导致 R=0.05.
请使用 eval/hosv_ablation.py 替代.

三种配置:
  A: Baseline (纯pattern检测, 无CJ)
  B: CJ-FM (约束收集+FM消元+边界推理, 无仿射)
  C: CJ-PSACJ (仿射证明+FM消元+边界推理, 完整版)

重点关注: 仿射证明能将多少INCONCLUSIVE转为PROVEN_SAFE.
"""
from __future__ import annotations
import json, os, sys, time
from pathlib import Path
from typing import Dict, List, Tuple

_DEEMO_ROOT = Path(__file__).parent.parent
if str(_DEEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(_DEEMO_ROOT))

SAMPLE_DIR = _DEEMO_ROOT / "tests" / "cve_samples" / "heap_overflow"
GT_PATH = SAMPLE_DIR / "ground_truth.json"
OUTPUT_DIR = _DEEMO_ROOT / "eval" / "results"

from core.cj_constraint_types import SolverVerdict
from core.heap_overflow_detector import detect_heap_overflow
from core.cj_solver import ConstraintJoinSolver
from core.cj_constraint_collector import collect_constraints


def load_gt() -> Dict:
    with open(GT_PATH, encoding='utf-8') as f:
        return json.load(f)


def read_source(name: str) -> str:
    d = SAMPLE_DIR / name
    c_files = list(d.glob("*.c"))
    return c_files[0].read_text(encoding='utf-8', errors='replace') if c_files else ""


def to_ir(source: str) -> List[str]:
    """从C源码生成IR行."""
    from core.ir_normalizer import normalize_ir
    lines = [l.strip() for l in source.splitlines()
             if l.strip() and not l.strip().startswith(('/*', '*', '//'))]
    return normalize_ir("\n".join(lines)) if lines else lines


def classify(count: int, expected_vuln: bool) -> str:
    has = count > 0
    if expected_vuln and has: return "TP"
    if expected_vuln and not has: return "FN"
    if not expected_vuln and has: return "FP"
    return "TN"


def metrics(verdicts: List[str]) -> Dict:
    tp = verdicts.count("TP"); fp = verdicts.count("FP")
    tn = verdicts.count("TN"); fn = verdicts.count("FN")
    p = tp/(tp+fp) if (tp+fp) > 0 else 0.0
    r = tp/(tp+fn) if (tp+fn) > 0 else 0.0
    f1 = 2*p*r/(p+r) if (p+r) > 0 else 0.0
    fpr = fp/(fp+tn) if (fp+tn) > 0 else 0.0
    return {"TP": tp, "FP": fp, "TN": tn, "FN": fn,
            "P": round(p,4), "R": round(r,4), "F1": round(f1,4),
            "FPR": round(fpr,4)}


def run_baseline(ir_lines, source):
    return detect_heap_overflow(ir_lines, source)


def run_cj_fm(candidates, ir_lines, source):
    """配置B: 仅FM消元+边界推理, 跳过仿射."""
    kept = []
    stats = {"safe": 0, "overflow": 0, "inconclusive": 0}
    for c in candidates:
        sys_obj = collect_constraints(c, ir_lines, source)
        solver = ConstraintJoinSolver("x86_64")
        result = solver.solve(sys_obj)
        if result.verdict == SolverVerdict.PROVEN_SAFE:
            stats["safe"] += 1; continue
        if result.verdict == SolverVerdict.PROVEN_OVERFLOW:
            stats["overflow"] += 1
        else:
            stats["inconclusive"] += 1
        kept.append(c)
    return kept, stats


def run_cj_psacj(candidates, ir_lines, source):
    """配置C: 仿射证明优先, FM回退."""
    from core.cj_affine_bridge import try_affine_proof
    kept = []
    stats = {"affine_safe": 0, "affine_overflow": 0,
             "fm_safe": 0, "fm_overflow": 0, "inconclusive": 0}
    for c in candidates:
        ar = try_affine_proof(c, ir_lines, "x86_64")
        if ar is not None:
            if ar.verdict == SolverVerdict.PROVEN_SAFE:
                stats["affine_safe"] += 1; continue
            if ar.verdict == SolverVerdict.PROVEN_OVERFLOW:
                stats["affine_overflow"] += 1
                kept.append(c); continue

        sys_obj = collect_constraints(c, ir_lines, source)
        solver = ConstraintJoinSolver("x86_64")
        result = solver.solve(sys_obj)
        if result.verdict == SolverVerdict.PROVEN_SAFE:
            stats["fm_safe"] += 1; continue
        if result.verdict == SolverVerdict.PROVEN_OVERFLOW:
            stats["fm_overflow"] += 1
        else:
            stats["inconclusive"] += 1
        kept.append(c)
    return kept, stats


def main():
    gt = load_gt()
    samples = gt["samples"]
    configs = {
        "baseline": {"verdicts": [], "details": []},
        "cj_fm": {"verdicts": [], "details": []},
        "cj_psacj": {"verdicts": [], "details": []},
    }

    print(f"PSACJ Ablation on {len(samples)} samples\n")
    print(f"{'Sample':<40} {'Exp':<6} {'Base':<6} {'FM':<6} {'PSACJ':<6}")
    print("-" * 70)

    for name, info in sorted(samples.items()):
        expected = info["expected_vuln"]
        source = read_source(name)
        if not source: continue
        ir_lines = to_ir(source)

        base_cands = run_baseline(ir_lines, source)
        fm_cands, fm_st = run_cj_fm(list(base_cands), ir_lines, source)
        psacj_cands, ps_st = run_cj_psacj(list(base_cands), ir_lines, source)

        bv = classify(len(base_cands), expected)
        fv = classify(len(fm_cands), expected)
        pv = classify(len(psacj_cands), expected)

        configs["baseline"]["verdicts"].append(bv)
        configs["cj_fm"]["verdicts"].append(fv)
        configs["cj_psacj"]["verdicts"].append(pv)

        exp_str = "VULN" if expected else "SAFE"
        print(f"  {name:<40} {exp_str:<6} {bv:<6} {fv:<6} {pv:<6}")

        configs["baseline"]["details"].append(
            {"sample": name, "verdict": bv, "findings": len(base_cands)})
        configs["cj_fm"]["details"].append(
            {"sample": name, "verdict": fv, "findings": len(fm_cands),
             "stats": fm_st})
        configs["cj_psacj"]["details"].append(
            {"sample": name, "verdict": pv, "findings": len(psacj_cands),
             "stats": ps_st})

    print(f"\n{'='*60}\nPSACJ Ablation Summary\n{'='*60}")
    for cn, cd in configs.items():
        m = metrics(cd["verdicts"])
        print(f"  {cn:<15}: P={m['P']:.4f} R={m['R']:.4f} "
              f"F1={m['F1']:.4f} FPR={m['FPR']:.4f} "
              f"(TP={m['TP']} FP={m['FP']} TN={m['TN']} FN={m['FN']})")
        cd["metrics"] = m

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out = OUTPUT_DIR / "psacj_ablation.json"
    with open(out, 'w', encoding='utf-8') as f:
        json.dump(configs, f, indent=2, ensure_ascii=False)
    print(f"\nSaved: {out}")


if __name__ == "__main__":
    main()
