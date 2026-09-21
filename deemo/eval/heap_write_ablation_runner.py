"""

包含配置表、ground truth加载、分类/指标计算、LaTeX输出.
"""
from __future__ import annotations
import json, os, sys
from pathlib import Path
from typing import Dict, List

_DEEMO_ROOT = Path(__file__).parent.parent
if str(_DEEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(_DEEMO_ROOT))

from analysis.heap_overflow_types import HoResult, HoVerdict

SAMPLE_DIR = _DEEMO_ROOT / "tests" / "cve_samples" / "heap_overflow"
GT_PATH = SAMPLE_DIR / "ground_truth.json"
OUTPUT_DIR = _DEEMO_ROOT / "eval" / "results"

# 7种配置: A→G 逐步启用各维度
CONFIGS = {
    "A_PatternOnly": dict(
        enable_allocator=False, enable_guard=False,
        enable_constraint_graph=False, enable_interproc=False,
        enable_accumulation=False, enable_apas=False),
    "B_PlusAllocator": dict(
        enable_allocator=True, enable_guard=False,
        enable_constraint_graph=False, enable_interproc=False,
        enable_accumulation=False, enable_apas=False),
    "C_PlusGuard": dict(
        enable_allocator=True, enable_guard=True,
        enable_constraint_graph=False, enable_interproc=False,
        enable_accumulation=False, enable_apas=False),
    "D_PlusConstraintGraph": dict(
        enable_allocator=True, enable_guard=True,
        enable_constraint_graph=True, enable_interproc=False,
        enable_accumulation=False, enable_apas=False),
    "E_PlusInterproc": dict(
        enable_allocator=True, enable_guard=True,
        enable_constraint_graph=True, enable_interproc=True,
        enable_accumulation=False, enable_apas=False),
    "F_PlusAccumulation": dict(
        enable_allocator=True, enable_guard=True,
        enable_constraint_graph=True, enable_interproc=True,
        enable_accumulation=True, enable_apas=False),
    "G_FullHOSV_PlusAPAS": dict(
        enable_allocator=True, enable_guard=True,
        enable_constraint_graph=True, enable_interproc=True,
        enable_accumulation=True, enable_apas=True),
}


def load_gt() -> Dict:
    with open(GT_PATH, encoding='utf-8') as f:
        return json.load(f)


def read_source(name: str) -> str:
    d = SAMPLE_DIR / name
    c_files = list(d.glob("*.c"))
    return c_files[0].read_text(encoding='utf-8', errors='replace') if c_files else ""


def classify(verdicts: List[HoResult], expected_vuln: bool) -> str:
    has_vuln = any(v.verdict == HoVerdict.VULN for v in verdicts)
    if expected_vuln and has_vuln:
        return "TP"
    if expected_vuln and not has_vuln:
        return "FN"
    if not expected_vuln and has_vuln:
        return "FP"
    return "TN"


def metrics(verdict_labels: List[str]) -> Dict:
    tp = verdict_labels.count("TP")
    fp = verdict_labels.count("FP")
    tn = verdict_labels.count("TN")
    fn = verdict_labels.count("FN")
    p = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    r = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return {"TP": tp, "FP": fp, "TN": tn, "FN": fn,
            "P": round(p, 4), "R": round(r, 4), "F1": round(f1, 4),
            "FPR": round(fpr, 4)}


def write_latex(configs_results: Dict, out_tex: Path):
    tex_lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{堆写模式验证 Progressive Ablation "
        r"— per-feature contribution to heap overflow detection.}",
        r"\label{tab:heap_write_ablation}",
        r"\begin{tabular}{lrrrrrrrr}",
        r"\toprule",
        r"Config & TP & FP & TN & FN & Precision & Recall & F1 & FPR \\",
        r"\midrule",
    ]
    for cn, cd in configs_results.items():
        m = cd["metrics"]
        tex_lines.append(
            f"  {cn} & {m['TP']} & {m['FP']} & {m['TN']} & {m['FN']} & "
            f"{m['P']:.4f} & {m['R']:.4f} & {m['F1']:.4f} & "
            f"{m['FPR']:.4f} \\\\")
    tex_lines.append(r"\bottomrule")
    tex_lines.append(r"\end{tabular}")
    tex_lines.append(r"\end{table}")
    with open(out_tex, 'w', encoding='utf-8') as f:
        f.write('\n'.join(tex_lines))


__all__ = [
    'CONFIGS', 'SAMPLE_DIR', 'GT_PATH', 'OUTPUT_DIR',
    'load_gt', 'read_source', 'classify', 'metrics', 'write_latex',
]
