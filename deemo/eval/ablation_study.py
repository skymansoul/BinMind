#!/usr/bin/env python3
"""
CJ消融实验 — 量化各阶段对最终判定的独立贡献.

消融配置:
  A0: 禁用全部CJ (baseline, 纯pattern匹配)
  A1: 仅Step1常量代换 (无FM消元, 无安全性证明)
  A2: Step1+Step2安全性证明 (无溢出确认, 无FM边界)
  A3: Step1+Step2+Step3溢出确认 (无FM边界推理)
  A4: 全部Step1-4 (完整GAPSBV-CJ, 含FM边界推理)

输出: 每个配置在测试用例集上的TP/FP/TN/FN/P/R/F1/FPR.
"""
from __future__ import annotations
import json, os, sys, time
from pathlib import Path
from typing import Dict, List, Tuple

_DEEMO_ROOT = Path(__file__).parent.parent
if str(_DEEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(_DEEMO_ROOT))

from core.cj_constraint_types import (
    ConstraintType, SolverVerdict, LinearConstraint,
    ConstraintSystem, SolverResult,
)
from core.cj_fourier_motzkin import (
    fourier_motzkin_eliminate, check_feasibility, substitute_constant,
)
from core.cj_safety_prover import (
    _compute_usable_size, _compute_write_end,
)


class AblationSolver:
    """可配置消融的CJ求解器."""

    def __init__(self, enable_safety=True, enable_overflow=True,
                 enable_fm_boundary=True, const_only=False):
        self.enable_safety = enable_safety
        self.enable_overflow = enable_overflow
        self.enable_fm_boundary = enable_fm_boundary
        self.const_only = const_only

    def solve(self, sys_obj: ConstraintSystem) -> SolverResult:
        result = SolverResult()
        result.constraints_collected = len(sys_obj.constraints)

        simplified = self._simplify(sys_obj)
        result.constraints_used = len(simplified.constraints)

        if self.const_only:
            cv = self._try_constant_eval(simplified)
            if cv is not None:
                result.verdict = cv[0]
                result.reason = cv[1]
                return result

        if self.enable_safety:
            from core.cj_safety_prover import prove_write_safety
            safety = prove_write_safety(simplified, "x86_64")
            if safety is not None:
                result.verdict = SolverVerdict.PROVEN_SAFE
                result.reason = safety.reason
                result.confidence_delta = safety.confidence_delta
                return result

        if self.enable_overflow:
            from core.cj_safety_prover import prove_overflow
            overflow = prove_overflow(simplified, "x86_64")
            if overflow is not None:
                result.verdict = SolverVerdict.PROVEN_OVERFLOW
                result.reason = overflow.reason
                result.confidence_delta = overflow.confidence_delta
                return result

        if self.enable_fm_boundary:
            fm_result = self._fm_boundary_refine(simplified)
            if fm_result is not None:
                result.verdict = fm_result[0]
                result.reason = fm_result[1]
                return result

        result.verdict = SolverVerdict.INCONCLUSIVE
        result.reason = "ablation: insufficient stages to decide"
        return result

    def _simplify(self, sys_obj: ConstraintSystem) -> ConstraintSystem:
        simplified = ConstraintSystem(
            alloc_var=sys_obj.alloc_var, alloc_size=sys_obj.alloc_size,
            copy_var=sys_obj.copy_var, copy_size=sys_obj.copy_size,
            offset_var=sys_obj.offset_var, offset_val=sys_obj.offset_val,
            loop_var=sys_obj.loop_var, loop_bound=sys_obj.loop_bound,
            mnemonic=sys_obj.mnemonic, store_size=sys_obj.store_size,
        )
        bound_map: dict[str, float] = {}
        if sys_obj.alloc_size > 0:
            bound_map[sys_obj.alloc_var] = float(sys_obj.alloc_size)
        if sys_obj.copy_size > 0:
            bound_map[sys_obj.copy_var] = float(sys_obj.copy_size)
        if sys_obj.offset_val > 0 and sys_obj.offset_var:
            bound_map[sys_obj.offset_var] = float(sys_obj.offset_val)
        if sys_obj.loop_bound > 0 and sys_obj.loop_var:
            bound_map[sys_obj.loop_var] = float(sys_obj.loop_bound)
        for c in sys_obj.constraints:
            if c.is_constant_only():
                continue
            sub = substitute_constant(c, bound_map)
            if sub is not None:
                simplified.constraints.append(sub)
        return simplified

    def _fm_boundary_refine(self, sys_obj):
        alloc_usable = _compute_usable_size(sys_obj, "x86_64")
        if alloc_usable <= 0:
            return None
        write_end_expr, _ = _compute_write_end(sys_obj)
        if write_end_expr is None:
            return None
        from core.cj_fm_boundary import fm_bound_refine
        return fm_bound_refine(sys_obj, write_end_expr, alloc_usable)

    def _try_constant_eval(self, sys_obj):
        """纯常量比较: write_end和usable都已知时直接判定."""
        alloc_usable = _compute_usable_size(sys_obj, "x86_64")
        if alloc_usable <= 0:
            return None
        write_end_expr, desc = _compute_write_end(sys_obj)
        if write_end_expr is None:
            return None
        if write_end_expr:
            return None
        from core.cj_safety_prover import _evaluate_constant_write_end
        val = _evaluate_constant_write_end(sys_obj)
        if val is None:
            return None
        if val <= alloc_usable:
            return SolverVerdict.PROVEN_SAFE, f"const: {val} <= {alloc_usable}"
        return SolverVerdict.PROVEN_OVERFLOW, f"const: {val} > {alloc_usable}"


CONFIGS = {
    "A0_no_cj": {"safety": False, "overflow": False, "fm": False,
                 "const_only": False},
    "A1_const_only": {"safety": False, "overflow": False, "fm": False,
                      "const_only": True},
    "A2_safety": {"safety": True, "overflow": False, "fm": False,
                  "const_only": True},
    "A3_safety_overflow": {"safety": True, "overflow": True, "fm": False,
                           "const_only": True},
    "A4_full": {"safety": True, "overflow": True, "fm": True,
                "const_only": True},
}


def load_ablation_cases() -> List[Dict]:
    """构建消融测试用例集 — 覆盖各判定路径."""
    cases = []
    from core.cj_constraint_types import ConstraintSystem

    def add(name, sys_obj, is_vuln):
        cases.append({"name": name, "sys": sys_obj, "is_vuln": is_vuln})

    add("const_overflow", ConstraintSystem(
        alloc_size=64, store_size=8, offset_val=72, mnemonic='store'), True)
    add("const_safe", ConstraintSystem(
        alloc_size=64, store_size=8, offset_val=32, mnemonic='store'), False)
    add("loop_overflow", ConstraintSystem(
        alloc_size=32, store_size=1, loop_bound=64, loop_var='i',
        mnemonic='store'), True)
    add("strcpy_unbounded", ConstraintSystem(
        alloc_size=32, mnemonic='strcpy', copy_size=-1), True)
    add("memcpy_overflow", ConstraintSystem(
        alloc_size=32, mnemonic='memcpy', copy_size=64), True)
    add("memcpy_safe", ConstraintSystem(
        alloc_size=64, mnemonic='memcpy', copy_size=32), False)
    add("align_safe", ConstraintSystem(
        alloc_size=63, store_size=8, offset_val=62, mnemonic='store'), False)

    sys_g = ConstraintSystem(
        alloc_size=0, alloc_var='n', store_size=4,
        offset_var='n', mnemonic='store')
    sys_g.add(LinearConstraint(
        coefficients={'n': 1.0}, constant=-64, operator="<=",
        source=ConstraintType.GUARD_CONDITION, confidence=0.9,
        description="if(n>64) return"))
    add("guard_safe", sys_g, False)

    sys_g2 = ConstraintSystem(
        alloc_size=64, store_size=8, offset_var='n', mnemonic='store')
    sys_g2.add(LinearConstraint(
        coefficients={'n': 1.0}, constant=-65, operator=">=",
        source=ConstraintType.GUARD_CONDITION, confidence=0.9,
        description="if(n<65) return"))
    add("guard_overflow", sys_g2, True)

    return cases


def run_ablation() -> Tuple[List[Dict], Dict]:
    cases = load_ablation_cases()
    results = []
    summary = {}

    for config_name, cfg in CONFIGS.items():
        tp = fp = tn = fn = 0
        case_results = []

        for case in cases:
            solver = AblationSolver(
                enable_safety=cfg["safety"],
                enable_overflow=cfg["overflow"],
                enable_fm_boundary=cfg["fm"],
                const_only=cfg["const_only"],
            )
            result = solver.solve(case["sys"])
            verdict = result.verdict

            is_overflow = verdict == SolverVerdict.PROVEN_OVERFLOW
            is_safe = verdict == SolverVerdict.PROVEN_SAFE
            is_inconclusive = verdict == SolverVerdict.INCONCLUSIVE

            if case["is_vuln"]:
                if is_overflow:
                    tp += 1; pred = "TP"
                else:
                    fn += 1; pred = "FN"
            else:
                if is_safe:
                    tn += 1; pred = "TN"
                elif is_overflow:
                    fp += 1; pred = "FP"
                else:
                    tn += 1; pred = "TN"

            case_results.append({
                "case": case["name"], "config": config_name,
                "verdict": verdict.value, "expected": case["is_vuln"],
                "pred": pred, "reason": result.reason[:80],
            })

        p = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        r = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2*p*r / (p+r) if (p+r) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        summary[config_name] = {
            "TP": tp, "FP": fp, "TN": tn, "FN": fn,
            "precision": round(p, 4), "recall": round(r, 4),
            "f1": round(f1, 4), "fp_rate": round(fpr, 4),
            "total": len(cases),
        }
        results.extend(case_results)

    return results, summary


def print_report(results: List[Dict], summary: Dict):
    print(f"\n{'='*80}")
    print(f" CJ Ablation Study — Stage Contribution Analysis")
    print(f"{'='*80}")
    print(f"{'Config':<28} {'TP':>3} {'FP':>3} {'TN':>3} {'FN':>3} "
          f"{'P':>6} {'R':>6} {'F1':>6} {'FPR':>6}")
    print("-" * 80)
    for name in CONFIGS:
        s = summary[name]
        print(f"{name:<28} {s['TP']:>3} {s['FP']:>3} {s['TN']:>3} {s['FN']:>3} "
              f"{s['precision']:>6.2f} {s['recall']:>6.2f} "
              f"{s['f1']:>6.2f} {s['fp_rate']:>6.2f}")
    print("=" * 80)

    print(f"\nDetailed case results:")
    for r in results:
        if r["pred"] in ("FP", "FN"):
            print(f"  [{r['config']}] {r['case']}: {r['verdict']} "
                  f"(expected {'VULN' if r['expected'] else 'SAFE'}) "
                  f"[{r['pred']}]")


def main():
    results, summary = run_ablation()
    print_report(results, summary)
    out_dir = _DEEMO_ROOT / "eval" / "results"
    out_dir.mkdir(parents=True, exist_ok=True)
    with open(out_dir / "ablation_results.json", "w") as f:
        json.dump({"results": results, "summary": summary}, f, indent=2)
    print(f"\nResults saved to {out_dir / 'ablation_results.json'}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
