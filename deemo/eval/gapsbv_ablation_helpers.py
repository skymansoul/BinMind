"""

包含: 样本发现/标注/阶段应用/交叉误报/LaTeX生成.
"""
from __future__ import annotations

import os, re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

HEAP_ROOTS = [
    'samples/cve', 'samples/heap_overflow',
    'samples/cve_heap_overflow', 'tests/cve_samples_heap',
    'tests/cve_samples', 'tests/heap_overflow_samples',
]


@dataclass
class SampleMeta:
    name: str
    path: str
    source: str
    is_vuln: bool
    vuln_type: str
    alloc_count: int = 0
    store_count: int = 0


def discover_heap_samples() -> List[SampleMeta]:
    """发现所有含 vuln.c 的堆相关样本, 自动标注 ground truth."""
    samples = []
    seen = set()
    for root_name in HEAP_ROOTS:
        root = os.path.join(BASE, root_name)
        if not os.path.isdir(root):
            continue
        for sd in Path(root).iterdir():
            if not sd.is_dir() or sd.name in seen:
                continue
            seen.add(sd.name)
            vuln_c = sd / 'vuln.c'
            if not vuln_c.exists():
                continue
            try:
                source = vuln_c.read_text(encoding='utf-8', errors='replace')
            except Exception:
                continue
            is_vuln, vuln_type = _infer_ground_truth(sd.name, source)
            samples.append(SampleMeta(
                name=sd.name, path=str(sd), source=source,
                is_vuln=is_vuln, vuln_type=vuln_type,
            ))
    return samples


def _infer_ground_truth(name: str, source: str) -> Tuple[bool, str]:
    """推断样本的 ground truth. 优先级: 目录名 → 注释标记 → 代码特征."""
    n = name.lower()
    if any(k in n for k in ('safe_', 'fp_', 'false_positive', 'tn_')):
        return (False, 'safe')
    if (n.startswith('cve-') or n.startswith('cve_')):
        if any(k in n for k in ('overflow', 'intovf', 'heap', 'nullptr')):
            return (True, 'heap_overflow')
    if any(k in n for k in ('overflow', 'vuln')):
        if 'heap' in n or 'overflow' in n:
            return (True, 'heap_overflow')

    src_lower = source.lower()
    if 'false positive' in src_lower and 'heap' in src_lower:
        return (False, 'safe')
    if 'heap overflow' in src_lower or 'buffer overflow' in src_lower:
        if 'safe' not in n:
            return (True, 'heap_overflow')

    alloc_sizes = re.findall(r'(?:malloc|calloc)\s*\(\s*(\d+)', source)
    store_sizes = re.findall(r'(?:memcpy|memset)\s*\([^,]+,\s*[^,]*,\s*(\d+)', source)
    for a_s in alloc_sizes:
        for w_s in store_sizes:
            if int(w_s) > int(a_s):
                return (True, 'heap_overflow')

    has_malloc = bool(re.search(r'\b(?:malloc|calloc|realloc)\s*\(', source))
    has_write = bool(re.search(
        r'\b(?:memcpy|strcpy|strcat|sprintf|memset)\s*\(', source))
    if has_malloc and has_write:
        return (True, 'heap_overflow')
    return (False, 'unknown')


def apply_stage(integrator, stage_idx: int, candidates: List,
                src_lines: List[str]) -> Tuple[List, int, int]:
    """对候选列表应用单个阶段, 返回 (kept, hard_filtered, soft_adjusted)."""
    from analysis.fp_filter_stages import stage1_allocator_semantics
    from analysis.fp_filter_stages_c_source import (
        stage2_guard_aware_c, stage3_size_constraints_c,
        stage4_proof_obligations_c, stage5_slack_space_c,
        stage6_value_range_c, stage7_non_heap_c,
    )

    if stage_idx == 1:
        kept = stage1_allocator_semantics(integrator, candidates)
        hard = len(candidates) - len(kept)
        return kept, hard, 0
    elif stage_idx == 2:
        kept, removed = stage2_guard_aware_c(integrator, candidates, src_lines)
        return kept, removed, 0
    elif stage_idx == 3:
        kept, adjusted = stage3_size_constraints_c(integrator, candidates, src_lines)
        return kept, 0, adjusted
    elif stage_idx == 4:
        kept, hard, soft = stage4_proof_obligations_c(
            integrator, candidates, src_lines)
        return kept, hard, soft
    elif stage_idx == 5:
        kept, adjusted = stage5_slack_space_c(integrator, candidates)
        return kept, 0, adjusted
    elif stage_idx == 6:
        kept, adjusted = stage6_value_range_c(integrator, candidates, src_lines)
        return kept, 0, adjusted
    elif stage_idx == 7:
        kept, removed = stage7_non_heap_c(integrator, candidates, src_lines)
        return kept, removed, 0
    return candidates, 0, 0


def get_source_lines(samples: List[SampleMeta], name: str) -> List[str]:
    for s in samples:
        if s.name == name:
            return s.source.splitlines()
    return []


def compute_cross_fp(sample_results: Dict, samples: List[SampleMeta]) -> Dict:
    """计算交叉误报: 非堆样本上堆检测器的告警率."""
    cross = {}
    for s in samples:
        if s.vuln_type in ('safe', 'unknown'):
            continue
        tp_name = s.vuln_type
        if tp_name not in cross:
            cross[tp_name] = {'total': 0, 'with_alerts': 0}
        cross[tp_name]['total'] += 1
        if sample_results[s.name]['baseline_count'] > 0:
            cross[tp_name]['with_alerts'] += 1

    result = {}
    for tp_name, stats in cross.items():
        rate = stats['with_alerts'] / max(1, stats['total']) * 100
        result[tp_name] = {
            'total_samples': stats['total'],
            'samples_with_heap_alerts': stats['with_alerts'],
            'cross_fp_rate_pct': round(rate, 1),
        }
    return result


def generate_latex_table(report: Dict, out_path: str) -> str:
    """生成消融表 LaTeX."""
    rows = []
    for s in report['stages']:
        rows.append(
            f"  {s['stage']} & {s['input_count']} & {s['output_count']} & "
            f"{s['hard_filtered']} & {s['soft_adjusted']} & "
            f"{s['TP']} & {s['FP']} & {s['TN']} & "
            f"{s['FN']} & {s['precision']:.4f} & {s['recall']:.4f} & "
            f"{s['f1']:.4f} \\\\"
        )

    tex = r"""\begin{table}[t]
\centering
\caption{GAPSBV Seven-Stage Ablation Study — per-stage hard/soft filtering, TP/FP/Precision/Recall/F1.}
\label{tab:gapsbv_ablation}
\begin{tabular}{lrrrrrrrrrrr}
\toprule
Stage & In & Out & Hard & Soft & TP & FP & TN & FN & Prec & Recall & F1 \\
\midrule
""" + '\n'.join(rows) + r"""
\bottomrule
\end{tabular}
\end{table}"""

    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(tex)
    return tex


__all__ = [
    'SampleMeta', 'discover_heap_samples', 'apply_stage',
    'get_source_lines', 'compute_cross_fp', 'generate_latex_table',
]
