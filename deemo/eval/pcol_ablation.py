#!/usr/bin/env python3
"""
PCOL 逐阶段消融实验 — 量化PCOL各子模块对UAF误报过滤的增量贡献.

四种配置:
  B0: HOIG-only         — 仅HoigBuilder (对象身份追踪, 无路径条件分析)
  B1: HOIG+Mutex        — +路径条件互斥检测
  B2: HOIG+Mutex+EarlyRet — +early-return不可达检测
  B3: HOIG+Full-PCOL    — +reassign检测 (完整PCOL)

输出: JSON + CSV + LaTeX 表格
"""
from __future__ import annotations
import csv, json, os, re, sys, time
from pathlib import Path
from typing import Dict, List

_DEEMO = Path(__file__).resolve().parent.parent
if str(_DEEMO) not in sys.path:
    sys.path.insert(0, str(_DEEMO))

from analysis.uaf_hoig_builder import HoigBuilder
from analysis.uaf_hoig_types import UafHoigVerdict
from analysis.uaf_pcol_constraints import (
    extract_free_path_conditions, check_path_mutex,
)
from analysis.uaf_pcol_verifier import (
    _check_early_return, _check_reassign,
)

OUTPUT_DIR = _DEEMO / "eval" / "results"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

from eval.pcol_ablation_samples import (
    MUTEX_SAMPLES, EARLY_SAMPLES, REASSIGN_SAMPLES,
    CONFIRMED_SAMPLES, NULLIFY_SAMPLES, ALL_SAMPLES,
)


# 消融配置实现

def _hoig_confirmed(code: str, name: str) -> List[UafHoigVerdict]:
    """获取HOIG CONFIRMED verdicts."""
    builder = HoigBuilder()
    _, _, verdicts = builder.build(code, name)
    return [v for v in verdicts if v.verdict == 'CONFIRMED']


def _label(has_confirmed: bool) -> str:
    return 'CONFIRMED' if has_confirmed else 'SAFE'


def run_b0_hoig_only(sample) -> str:
    """B0: 仅HoigBuilder, 无PCOL."""
    name, code, expected = sample
    confirmed = _hoig_confirmed(code, name)
    return _label(bool(confirmed))


def run_b1_mutex(sample) -> str:
    """B1: HOIG + 路径条件互斥检测."""
    name, code, expected = sample
    confirmed = _hoig_confirmed(code, name)
    if not confirmed:
        return 'SAFE'
    lines = code.split('\n')
    for v in confirmed:
        free_idx = max(0, v.free_line - 1)
        use_idx = max(0, v.use_line - 1)
        if free_idx >= len(lines) or use_idx >= len(lines):
            continue
        fc, uc = extract_free_path_conditions(lines, free_idx, use_idx)
        if fc and uc:
            is_mutex, _ = check_path_mutex(fc, uc)
            if is_mutex:
                return 'SAFE'
    return 'CONFIRMED'


def run_b2_mutex_earlyret(sample) -> str:
    """B2: HOIG + 互斥 + early-return检测."""
    name, code, expected = sample
    confirmed = _hoig_confirmed(code, name)
    if not confirmed:
        return 'SAFE'
    lines = code.split('\n')
    for v in confirmed:
        free_idx = max(0, v.free_line - 1)
        use_idx = max(0, v.use_line - 1)
        if free_idx >= len(lines) or use_idx >= len(lines):
            continue
        fc, uc = extract_free_path_conditions(lines, free_idx, use_idx)
        if fc and uc:
            is_mutex, _ = check_path_mutex(fc, uc)
            if is_mutex:
                return 'SAFE'
        if _check_early_return(lines, free_idx, use_idx):
            return 'SAFE'
    return 'CONFIRMED'


def run_b3_full_pcol(sample) -> str:
    """B3: HOIG + 互斥 + early-return + reassign (完整PCOL)."""
    name, code, expected = sample
    confirmed = _hoig_confirmed(code, name)
    if not confirmed:
        return 'SAFE'
    lines = code.split('\n')
    for v in confirmed:
        free_idx = max(0, v.free_line - 1)
        use_idx = max(0, v.use_line - 1)
        if free_idx >= len(lines) or use_idx >= len(lines):
            continue
        fc, uc = extract_free_path_conditions(lines, free_idx, use_idx)
        if fc and uc:
            is_mutex, _ = check_path_mutex(fc, uc)
            if is_mutex:
                return 'SAFE'
        if _check_early_return(lines, free_idx, use_idx):
            return 'SAFE'
        use_var = getattr(v, 'use_var', '')
        if use_var and _check_reassign(lines, free_idx, use_idx, use_var):
            return 'SAFE'
    return 'CONFIRMED'


CONFIGS = [
    ('B0_HOIG_Only', run_b0_hoig_only),
    ('B1_Mutex', run_b1_mutex),
    ('B2_Mutex_EarlyRet', run_b2_mutex_earlyret),
    ('B3_Full_PCOL', run_b3_full_pcol),
]


def _metrics(records):
    tp = sum(1 for r in records
             if r['expected'] == 'CONFIRMED' and r['verdict'] == 'CONFIRMED')
    fp = sum(1 for r in records
             if r['expected'] == 'SAFE' and r['verdict'] == 'CONFIRMED')
    tn = sum(1 for r in records
             if r['expected'] == 'SAFE' and r['verdict'] == 'SAFE')
    fn = sum(1 for r in records
             if r['expected'] == 'CONFIRMED' and r['verdict'] != 'CONFIRMED')
    p = tp / max(1, tp + fp)
    r = tp / max(1, tp + fn)
    f1 = 2 * p * r / max(0.001, p + r)
    fpr = fp / max(1, fp + tn)
    return {'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn,
            'precision': round(p, 4), 'recall': round(r, 4),
            'f1': round(f1, 4), 'fpr': round(fpr, 4)}


def run_ablation():
    results = {}
    csv_rows = []

    for config_name, runner in CONFIGS:
        records = []
        for name, code, expected in ALL_SAMPLES:
            t0 = time.perf_counter()
            verdict = runner((name, code, expected))
            dt = (time.perf_counter() - t0) * 1000
            correct = (verdict == expected)
            records.append({
                'sample': name, 'expected': expected,
                'verdict': verdict, 'correct': correct,
                'time_ms': round(dt, 3),
            })
            csv_rows.append({
                'config': config_name, 'sample': name,
                'expected': expected, 'verdict': verdict,
                'correct': correct, 'time_ms': round(dt, 3),
            })
        m = _metrics(records)
        results[config_name] = {'metrics': m, 'details': records}
        print(f"  {config_name:<22s} P={m['precision']:.4f} "
              f"R={m['recall']:.4f} F1={m['f1']:.4f} "
              f"FPR={m['fpr']:.4f} "
              f"TP={m['tp']} FP={m['fp']} TN={m['tn']} FN={m['fn']}")

    # JSON
    json_path = OUTPUT_DIR / 'pcol_ablation.json'
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n  JSON: {json_path}")

    # CSV
    csv_path = OUTPUT_DIR / 'pcol_ablation.csv'
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['config', 'sample',
                                          'expected', 'verdict',
                                          'correct', 'time_ms'])
        w.writeheader()
        w.writerows(csv_rows)
    print(f"  CSV:  {csv_path}")

    # LaTeX
    tex_path = _DEEMO / 'eval' / 'pcol_ablation_table.tex'
    _write_latex(results, tex_path)
    print(f"  LaTeX: {tex_path}")

    return results


def _write_latex(results, path):
    with open(path, 'w', encoding='utf-8') as f:
        f.write(r"\begin{table}[htbp]" + "\n")
        f.write(r"\centering" + "\n")
        f.write(r"\caption{PCOL Ablation Study --- "
                r"Incremental Contribution of Path-Condition "
                r"Filtering Submodules}" + "\n")
        f.write(r"\label{tab:pcol_ablation}" + "\n")
        f.write(r"\begin{tabular}{lrrrrrrrr}" + "\n")
        f.write(r"\toprule" + "\n")
        f.write(r"Config & TP & FP & TN & FN & P & R & F1 & FPR \\"
                + "\n")
        f.write(r"\midrule" + "\n")
        for cfg_name, data in results.items():
            m = data['metrics']
            f.write(f"  {cfg_name} & {m['tp']} & {m['fp']} & {m['tn']} "
                    f"& {m['fn']} & {m['precision']:.4f} "
                    f"& {m['recall']:.4f} & {m['f1']:.4f} "
                    f"& {m['fpr']:.4f} \\\\\n")
        f.write(r"\bottomrule" + "\n")
        f.write(r"\end{tabular}" + "\n")
        f.write(r"\end{table}" + "\n")


if __name__ == '__main__':
    print("=" * 64)
    print("PCOL Ablation Study")
    print("=" * 64)
    run_ablation()
    print("=" * 64)
