"""
GAPSBV 七阶段FP削减验证 — 对17个CVE堆溢出样本逐阶段测量FP削减效果.

与 gapsbv_benchmark.py 的区别:
  - gapsbv_benchmark: baseline vs enhanced 二分类对比 (大样本集)
  - 本脚本: 七阶段级联, 逐阶段统计, 生成消融表 (论文 Table 2)
  - 直接消费 analysis.fp_reduction_integrator.FPReductionIntegrator

运行: python eval/validate_fp_reduction.py [--json output.json] [--latex table.tex]
"""

from __future__ import annotations

import json, os, re, sys, time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _BASE)

# ── ground truth: 从 collect_results.py 的 EXPECTED 镜像 ──
EXPECTED = {
    "cve_01_simple_overflow":       (True,  1, "base overflow"),
    "cve_02_off_by_one":            (True,  1, "off-by-one"),
    "cve_03_int_overflow_calc":     (True,  1, "integer overflow calc"),
    "cve_04_strcpy_overflow":       (True,  1, "strcpy overflow"),
    "cve_05_loop_overflow":         (True,  1, "loop overflow"),
    "cve_06_user_controlled_size":  (True,  1, "user-controlled size"),
    "cve_07_realloc_overflow":      (True,  1, "realloc overflow"),
    "cve_08_calloc_overflow":       (True,  1, "calloc overflow"),
    "cve_09_safe_but_triggers_fp":  (False, 0, "FP — alignment safety"),
    "cve_10_input_constrained_safe":(False, 0, "FP — constrained input"),
    "cve_11_memcpy_arith_size":     (True,  1, "memcpy arith overflow"),
    "cve_12_alignment_edge":        (True,  1, "alignment edge"),
    "cve_13_struct_field_pattern":  (False, 0, "FP — struct field in bounds"),
    "cve_14_multi_chunk":           (True,  1, "multi-chunk overflow"),
    "cve_15_constrained_input":     (True,  1, "constrained but overflowed"),
    "cve_16_real_world_pattern":    (True,  1, "real-world pattern"),
    "cve_17_multi_field_struct":    (False, 0, "FP — multi-field stride safe"),
}

SAMPLE_DIR = os.path.join(_BASE, "tests", "cve_samples", "heap_overflow")


@dataclass
class StageResult:
    """单阶段结果."""
    name: str
    input_count: int = 0
    output_count: int = 0
    hard_filtered: int = 0
    soft_adjusted: int = 0
    # 分类统计
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0


def read_sample_source(sample_name: str) -> str:
    """读取样本C源码."""
    d = Path(SAMPLE_DIR) / sample_name
    for f in d.glob("*.c"):
        return f.read_text(encoding="utf-8", errors="replace")
    return ""


def run_detection(source: str) -> List[Any]:
    """对C源码运行检测, 返回 HeapOverflowCandidate 列表."""
    try:
        from analysis.c_source_analyzer import analyze_c_source
        return analyze_c_source(source)
    except ImportError:
        return []


def classify_candidates(
    candidates: List[Any],
    sample_name: str,
    is_vuln: bool,
    min_findings: int,
) -> Tuple[str, int, int]:
    """将候选列表与ground truth比较, 返回 (verdict, tp_increment, fp_increment).

    判定逻辑:
      - is_vuln=True + 有检出 → TP
      - is_vuln=True + 无检出 → FN
      - is_vuln=False + 有检出 → FP (每个候选算一个FP)
      - is_vuln=False + 无检出 → TN
    """
    n = len(candidates)
    if is_vuln:
        if n >= min_findings:
            return ("TP", 1, 0)
        else:
            return ("FN", 0, 0)
    else:
        if n > 0:
            return ("FP", 0, n)
        else:
            return ("TN", 0, 0)


def run_validation() -> Dict:
    """主验证逻辑: 17样本 → 检测 → 七阶段削减 → 逐阶段统计."""
    import importlib

    samples = sorted(
        [d.name for d in Path(SAMPLE_DIR).iterdir()
         if d.is_dir() and d.name.startswith("cve_")])

    print(f"GAPSBV 七阶段FP削减验证 — {len(samples)} 样本")
    print("=" * 70)

# Phase 1: 收集所有样本的候选
    all_candidates: Dict[str, List[Any]] = {}
    all_sources: Dict[str, str] = {}

    for name in samples:
        src = read_sample_source(name)
        all_sources[name] = src
        if src:
            candidates = run_detection(src)
            all_candidates[name] = candidates
        else:
            all_candidates[name] = []

# Phase 2: 建立阶段0基线
    stage_names = [
        "S0_Baseline",
        "S1_AllocatorSemantics",
        "S2_GuardAwareWrites",
        "S3_SizeConstraints",
        "S4_ProofObligations",
        "S5_SlackSpace",
        "S6_ValueRange",
        "S7_NonHeapFilter",
    ]
    stages: List[StageResult] = []

    # S0: 基线 = 原始检测结果
    s0 = StageResult(name="S0_Baseline", input_count=0)
    for name in samples:
        is_vuln, min_f, _ = EXPECTED.get(name, (True, 1, ""))
        verdict, tp_delta, fp_delta = classify_candidates(
            all_candidates[name], name, is_vuln, min_f)
        if verdict == "TP":
            s0.tp += 1
        elif verdict == "FP":
            s0.fp += fp_delta
        elif verdict == "TN":
            s0.tn += 1
        elif verdict == "FN":
            s0.fn += 1
    s0.output_count = sum(len(v) for v in all_candidates.values())
    stages.append(s0)

# Phase 3: 逐阶段运行 FPReductionIntegrator
    try:
        from analysis.fp_reduction_integrator import FPReductionIntegrator
        from analysis.fp_filter_stages import (
            stage1_allocator_semantics, stage2_guard_aware,
            stage3_size_constraints, stage4_proof_obligations,
            stage5_slack_space, stage6_value_range, stage7_non_heap,
        )
        integrator = FPReductionIntegrator()
    except ImportError:
        print("ERROR: 无法导入 FPReductionIntegrator")
        integrator = None

    if integrator is not None:
        # 对每个样本独立运行七阶段管线
        for stage_idx in range(1, 8):
            stage_name = stage_names[stage_idx]
            sr = StageResult(name=stage_name)
            prev_stage = stages[stage_idx - 1]

            # 对每个样本应用当前阶段
            sample_candidates_after: Dict[str, List[Any]] = {}

            for name in samples:
                candidates = all_candidates.get(name, [])
                src = all_sources.get(name, "")
                src_lines = src.splitlines() if src else []

                # 调用 fp_filter_stages 的独立阶段函数
                if stage_idx == 1:
                    filtered = stage1_allocator_semantics(integrator, candidates)
                elif stage_idx == 2:
                    filtered, _ = stage2_guard_aware(integrator, candidates, src_lines)
                elif stage_idx == 3:
                    filtered, _ = stage3_size_constraints(integrator, candidates, src_lines)
                elif stage_idx == 4:
                    filtered, _, _ = stage4_proof_obligations(integrator, candidates, src_lines)
                elif stage_idx == 5:
                    filtered, _ = stage5_slack_space(integrator, candidates)
                elif stage_idx == 6:
                    filtered, _ = stage6_value_range(integrator, candidates, src_lines)
                elif stage_idx == 7:
                    filtered, _ = stage7_non_heap(integrator, candidates, src_lines)
                else:
                    filtered = candidates

                sample_candidates_after[name] = filtered

            # 统计本阶段分类
            for name in samples:
                is_vuln, min_f, _ = EXPECTED.get(name, (True, 1, ""))
                filtered = sample_candidates_after[name]
                verdict, tp_delta, fp_delta = classify_candidates(
                    filtered, name, is_vuln, min_f)
                if verdict == "TP":
                    sr.tp += 1
                elif verdict == "FP":
                    sr.fp += fp_delta
                elif verdict == "TN":
                    sr.tn += 1
                elif verdict == "FN":
                    sr.fn += 1

            sr.output_count = sum(len(v) for v in sample_candidates_after.values())
            sr.input_count = prev_stage.output_count
            sr.hard_filtered = max(0, prev_stage.output_count - sr.output_count)
            stages.append(sr)

            # 更新 all_candidates 为本阶段输出 (级联)
            all_candidates = sample_candidates_after

# Phase 4: 计算指标
    report = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_samples": len(samples),
        "stages": [],
    }

    for s in stages:
        report["stages"].append({
            "stage": s.name,
            "input_count": s.input_count,
            "output_count": s.output_count,
            "hard_filtered": s.hard_filtered,
            "soft_adjusted": s.soft_adjusted,
            "TP": s.tp, "FP": s.fp, "TN": s.tn, "FN": s.fn,
            "precision": round(s.precision, 4),
            "recall": round(s.recall, 4),
            "f1": round(s.f1, 4),
        })

# Phase 5: 输出
    print(f"\n{'Stage':<24} {'In':>4} {'Out':>4} {'Hard':>4} {'TP':>3} {'FP':>3} {'TN':>3} {'FN':>3} "
          f"{'Prec':>7} {'Recall':>7} {'F1':>7}")
    print("-" * 85)
    for s in report["stages"]:
        print(f"{s['stage']:<24} {s['input_count']:>4} {s['output_count']:>4} "
              f"{s['hard_filtered']:>4} {s['TP']:>3} {s['FP']:>3} {s['TN']:>3} {s['FN']:>3} "
              f"{s['precision']:>6.4f} {s['recall']:>6.4f} {s['f1']:>6.4f}")

    # FP削减率
    s0_fp = report["stages"][0]["FP"]
    s7_fp = report["stages"][-1]["FP"] if len(report["stages"]) > 1 else s0_fp
    if s0_fp > 0:
        reduction = (s0_fp - s7_fp) / s0_fp * 100
        print(f"\nFP削减: {s0_fp} → {s7_fp} ({reduction:.1f}%)")

    return report


def generate_latex_table(report: Dict) -> str:
    """从报告生成论文 Table 2 LaTeX."""
    rows = []
    for s in report["stages"]:
        rows.append(
            f"    {s['stage']} & {s['TP']} & {s['FP']} & {s['TN']} & {s['FN']} & "
            f"{s['precision']:.3f} & {s['recall']:.3f} & {s['f1']:.3f} \\\\"
        )

    return (
        "\\begin{table}[htbp]\n"
        "\\centering\n"
        "\\caption{GAPSBV Per-Stage Ablation Study (17 CVE Heap Overflow Samples)}\n"
        "\\label{tab:ablation}\n"
        "\\begin{tabular}{lccccccc}\n"
        "\\toprule\n"
        "Stage & TP & FP & TN & FN & Prec. & Recall & F1 \\\\\n"
        "\\midrule\n"
        + "\n".join(rows) + "\n"
        "\\bottomrule\n"
        "\\end{tabular}\n"
        "\\end{table}"
    )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="GAPSBV七阶段FP削减验证")
    parser.add_argument("--json", default="", help="输出JSON路径")
    parser.add_argument("--latex", default="", help="输出LaTeX表路径")
    args = parser.parse_args()

    report = run_validation()

    json_path = args.json or os.path.join(
        os.path.dirname(__file__), "fp_reduction_validation.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\nJSON report → {json_path}")

    if args.latex:
        tex = generate_latex_table(report)
        with open(args.latex, "w", encoding="utf-8") as f:
            f.write(tex)
        print(f"LaTeX table → {args.latex}")
