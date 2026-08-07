#!/usr/bin/env python3
"""
PCFC逐阶段消融实验 — 量化PCFC各子模块对格式串误报过滤的增量贡献.

四种配置:
  B0: FCPV-only          — 仅FCPV安全格求解器 (无路径条件分析)
  B1: FCPV+Mutex         — +路径条件互斥检测
  B2: FCPV+Mutex+EarlyRet — +early-return不可达检测
  B3: FCPV+Full-PCFC     — +复合条件分解 (完整PCFC)

输出: JSON + CSV + LaTeX 表格
"""
from __future__ import annotations
import csv, json, os, re, sys, time
from pathlib import Path
from typing import Dict, List, Tuple

_DEEMO = Path(__file__).resolve().parent.parent
if str(_DEEMO) not in sys.path:
    sys.path.insert(0, str(_DEEMO))

from core.fcpv_pipeline import run_fcpv
from core.fcpv_constraint_types import SafetyLabel
from core.pcfc_verifier import (
    _check_sink_early_return, _check_compound_mutex,
)
from analysis.uaf_pcol_constraints import extract_path_conditions, check_path_mutex
from eval.pcfc_ablation_samples import ALL_SAMPLES

OUTPUT_DIR = _DEEMO / "eval" / "results"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# 消融配置实现

def _fcpv_vuln(code: str) -> List:
    """获取FCPV VULN候选列表."""
    candidates = run_fcpv(code)
    return [c for c in candidates if c.label == SafetyLabel.VULN]


def _label(has_vuln: bool) -> str:
    return 'VULN' if has_vuln else 'SAFE'


def run_b0_fcpv_only(sample) -> str:
    """B0: 仅FCPV, 无PCFC."""
    _, code, _ = sample
    vuln = _fcpv_vuln(code)
    return _label(bool(vuln))


def run_b1_mutex(sample) -> str:
    """B1: FCPV + 路径条件互斥检测 (仅原子条件)."""
    _, code, _ = sample
    vulns = _fcpv_vuln(code)
    if not vulns:
        return 'SAFE'
    lines = code.split('\n')
    for c in vulns:
        sink_idx = max(0, c.sink.line - 1)
        if sink_idx >= len(lines):
            continue
        sink_conds = extract_path_conditions(lines, sink_idx)
        if not sink_conds:
            continue
        for taint in c.taints:
            taint_idx = max(0, taint.source_line - 1)
            if taint_idx >= len(lines):
                continue
            taint_conds = extract_path_conditions(lines, taint_idx)
            if taint_conds:
                is_mutex, _ = check_path_mutex(taint_conds, sink_conds)
                if is_mutex:
                    return 'SAFE'
    return 'VULN'


def run_b2_mutex_earlyret(sample) -> str:
    """B2: FCPV + 互斥 + early-return检测."""
    _, code, _ = sample
    vulns = _fcpv_vuln(code)
    if not vulns:
        return 'SAFE'
    lines = code.split('\n')
    for c in vulns:
        sink_idx = max(0, c.sink.line - 1)
        if sink_idx >= len(lines):
            continue
        # early-return
        if _check_sink_early_return(lines, sink_idx):
            return 'SAFE'
        # mutex (原子)
        sink_conds = extract_path_conditions(lines, sink_idx)
        if sink_conds:
            for taint in c.taints:
                taint_idx = max(0, taint.source_line - 1)
                if taint_idx >= len(lines):
                    continue
                taint_conds = extract_path_conditions(lines, taint_idx)
                if taint_conds:
                    is_mutex, _ = check_path_mutex(taint_conds, sink_conds)
                    if is_mutex:
                        return 'SAFE'
    return 'VULN'


def run_b3_full_pcfc(sample) -> str:
    """B3: FCPV + 互斥(含复合) + early-return (完整PCFC)."""
    _, code, _ = sample
    vulns = _fcpv_vuln(code)
    if not vulns:
        return 'SAFE'
    lines = code.split('\n')
    for c in vulns:
        sink_idx = max(0, c.sink.line - 1)
        if sink_idx >= len(lines):
            continue
        # early-return
        if _check_sink_early_return(lines, sink_idx):
            return 'SAFE'
        # mutex (含复合条件分解)
        sink_conds = extract_path_conditions(lines, sink_idx)
        if sink_conds:
            for taint in c.taints:
                taint_idx = max(0, taint.source_line - 1)
                if taint_idx >= len(lines):
                    continue
                taint_conds = extract_path_conditions(lines, taint_idx)
                if taint_conds:
                    is_mutex, _ = _check_compound_mutex(
                        taint_conds, sink_conds)
                    if is_mutex:
                        return 'SAFE'
    return 'VULN'


CONFIGS = [
    ('B0_FCPV_Only', run_b0_fcpv_only),
    ('B1_Mutex', run_b1_mutex),
    ('B2_Mutex_EarlyRet', run_b2_mutex_earlyret),
    ('B3_Full_PCFC', run_b3_full_pcfc),
]


def _metrics(records):
    tp = sum(1 for r in records
             if r['expected'] == 'VULN' and r['verdict'] == 'VULN')
    fp = sum(1 for r in records
             if r['expected'] == 'SAFE' and r['verdict'] == 'VULN')
    tn = sum(1 for r in records
             if r['expected'] == 'SAFE' and r['verdict'] == 'SAFE')
    fn = sum(1 for r in records
             if r['expected'] == 'VULN' and r['verdict'] != 'VULN')
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
    json_path = OUTPUT_DIR / 'pcfc_ablation.json'
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n  JSON: {json_path}")

    # CSV
    csv_path = OUTPUT_DIR / 'pcfc_ablation.csv'
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['config', 'sample',
                                          'expected', 'verdict',
                                          'correct', 'time_ms'])
        w.writeheader()
        w.writerows(csv_rows)
    print(f"  CSV:  {csv_path}")

    # LaTeX
    tex_path = _DEEMO / 'eval' / 'pcfc_ablation_table.tex'
    _write_latex(results, tex_path)
    print(f"  LaTeX: {tex_path}")

    return results


def _write_latex(results, path):
    with open(path, 'w', encoding='utf-8') as f:
        f.write(r"\begin{table}[htbp]" + "\n")
        f.write(r"\centering" + "\n")
        f.write(r"\caption{PCFC Ablation Study --- "
                r"Incremental Contribution of Path-Condition "
                r"Filtering for Format String Detection}" + "\n")
        f.write(r"\label{tab:pcfc_ablation}" + "\n")
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
    print("PCFC Ablation Study")
    print("=" * 64)
    run_ablation()
    print("=" * 64)
