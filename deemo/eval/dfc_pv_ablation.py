#!/usr/bin/env python3
"""DFC-PV 逐阶段消融实验 — 量化各组件对 double-free 检测精度的增量贡献.

四种配置:
  A0: Baseline      — 旧 DFSV 检测器 (仅变量名匹配, 无 AOI, 无回调检测)
  A1: +AOI          — AOI 追踪 + 配对检测 + 别名链 (无路径安全证明, 无跨函数)
  A2: +PathSafety   — +路径敏感安全性证明 (realloc/NULL/互斥/freed flag)
  A3: Full          — 完整 DFC-PV (+跨函数包装链 +回调双释放)

输出: JSON + CSV + LaTeX 表格
入口: python eval/dfc_pv_ablation.py
"""
from __future__ import annotations
import csv, json, os, sys, time
from pathlib import Path
from typing import Dict, List, Tuple

_DEEMO = Path(__file__).resolve().parent.parent
if str(_DEEMO) not in sys.path:
    sys.path.insert(0, str(_DEEMO))

from analysis.dfc_pv_pipeline import detect_double_free_dfc
from analysis.dfc_pv_verifier import DfcPvVerifier
from analysis.dfc_pv_types import DfcVerdict
from analysis.dfc_pv_extractor import extract_events
from analysis.dfc_pv_resolver import AOITracker
from analysis.dfc_pv_path import PathAnalyzer
from analysis.dfc_pv_crossfunc import CrossFuncAnalyzer
from analysis.dfc_pv_helpers import _same_or_alias, _check_path_safety
from analysis.double_free_src_verifier import DoubleFreeSrcVerifier

OUTPUT_DIR = _DEEMO / 'eval' / 'results'
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

SAMPLES_DIR = _DEEMO / 'tests' / 'cve_samples'
GT: Dict[str, int] = {}
for i in range(1, 16):
    GT[f'double_free_{i:02d}'] = 0 if i == 7 else 1
_ADV_SAFE = {18, 21, 24, 27, 29}
for i in range(16, 32):
    GT[f'df_adv_{i}'] = 0 if i in _ADV_SAFE else 1


# A0: Baseline DFSV
def run_a0(source: str) -> int:
    dfsv = DoubleFreeSrcVerifier()
    results = dfsv.verify(source)
    return 1 if results else 0


# A1: AOI only (无路径安全, 无跨函数)
def run_a1(source: str) -> int:
    lines = source.splitlines()
    allocs, frees, aliases, nulls, reallocs, func_map = extract_events(source)
    if not frees:
        return 0
    aoi = AOITracker(allocs, reallocs, nulls, aliases)
    for i in range(len(frees)):
        for j in range(i + 1, len(frees)):
            a, b = frees[i], frees[j]
            if _same_alloc(a, b, aoi):
                if not aoi.has_realloc_between(a.base_var, a.line, b.line):
                    return 1
    return 0


# A2: +PathSafety (AOI + 路径安全, 无跨函数)
def run_a2(source: str) -> int:
    lines = source.splitlines()
    allocs, frees, aliases, nulls, reallocs, func_map = extract_events(source)
    if not frees:
        return 0
    aoi = AOITracker(allocs, reallocs, nulls, aliases)
    pa = PathAnalyzer(lines)
    for i in range(len(frees)):
        for j in range(i + 1, len(frees)):
            a, b = frees[i], frees[j]
            if _same_alloc(a, b, aoi):
                if aoi.is_null_before_free(a.base_var, a.line):
                    continue
                if aoi.has_realloc_between(a.base_var, a.line, b.line):
                    continue
                if aoi.has_unconditional_null_between(a.base_var, a.line, b.line):
                    continue
                if pa.is_mutually_exclusive(a.line, b.line):
                    continue
                flags = pa.find_freed_flags(source)
                if pa.has_freed_flag_between(a.line, b.line, flags):
                    continue
                if a.base_var == b.base_var and aoi.nodes:
                    ao = set(aoi.get_aoi_for_free(a))
                    bo = set(aoi.get_aoi_for_free(b))
                    if ao and bo and not (ao & bo):
                        continue
                return 1
    return 0


# A3: Full DFC-PV
def run_a3(source: str) -> int:
    findings = detect_double_free_dfc(source)
    return 1 if findings else 0


def _same_alloc(a, b, aoi) -> bool:
    if aoi.nodes:
        ao = aoi.get_aoi_for_free(a)
        bo = aoi.get_aoi_for_free(b)
        if ao and bo:
            return bool(set(ao) & set(bo))
    if a.base_var == b.base_var:
        return True
    return aoi.resolver.bidirectional_alias(a.base_var, b.base_var)


CONFIGS = [
    ('A0_Baseline', run_a0),
    ('A1_AOI', run_a1),
    ('A2_PathSafety', run_a2),
    ('A3_Full', run_a3),
]


def run_ablation() -> Dict:
    all_results = {}
    csv_rows = []

    for cfg_name, runner in CONFIGS:
        records = []
        for name in sorted(GT):
            src_path = SAMPLES_DIR / name / 'vuln.c'
            if not src_path.is_file():
                continue
            source = src_path.read_text(encoding='utf-8', errors='replace')
            t0 = time.perf_counter()
            detected = runner(source)
            dt = (time.perf_counter() - t0) * 1000
            exp = GT[name]
            correct = detected == exp
            records.append({
                'sample': name, 'expected': exp,
                'detected': detected, 'correct': correct,
                'time_ms': round(dt, 3),
            })
            csv_rows.append({
                'config': cfg_name, 'sample': name,
                'expected': exp, 'detected': detected,
                'correct': correct, 'time_ms': round(dt, 3),
            })
        m = _metrics(records)
        all_results[cfg_name] = {'metrics': m, 'details': records}
        print(f"  {cfg_name:<20s} P={m['precision']:.4f} R={m['recall']:.4f} "
              f"F1={m['f1']:.4f} FPR={m['fpr']:.4f} "
              f"TP={m['tp']} FP={m['fp']} TN={m['tn']} FN={m['fn']}")

    # JSON
    json_path = OUTPUT_DIR / 'dfc_pv_ablation.json'
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)
    print(f"\n  JSON: {json_path}")

    # CSV
    csv_path = OUTPUT_DIR / 'dfc_pv_ablation.csv'
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['config', 'sample',
                          'expected', 'detected', 'correct', 'time_ms'])
        w.writeheader()
        w.writerows(csv_rows)
    print(f"  CSV:  {csv_path}")

    # LaTeX
    tex_path = _DEEMO / 'eval' / 'dfc_pv_ablation_table.tex'
    _write_latex(all_results, tex_path)
    print(f"  LaTeX: {tex_path}")
    return all_results


def _metrics(records):
    tp = sum(1 for r in records if r['detected'] == 1 and r['expected'] == 1)
    fp = sum(1 for r in records if r['detected'] == 1 and r['expected'] == 0)
    fn = sum(1 for r in records if r['detected'] == 0 and r['expected'] == 1)
    tn = sum(1 for r in records if r['detected'] == 0 and r['expected'] == 0)
    p = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    r = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return {'precision': p, 'recall': r, 'f1': f1, 'fpr': fpr,
            'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn}


def _write_latex(results, path):
    with open(path, 'w', encoding='utf-8') as f:
        f.write(r"\begin{table}[htbp]" + "\n")
        f.write(r"\centering" + "\n")
        f.write(r"\caption{DFC-PV Ablation Study (31 samples)}" + "\n")
        f.write(r"\label{tab:dfc_pv_ablation}" + "\n")
        f.write(r"\begin{tabular}{lrrrrrrrr}" + "\n")
        f.write(r"\toprule" + "\n")
        f.write(r"Config & TP & FP & TN & FN & P & R & F1 & FPR \\" + "\n")
        f.write(r"\midrule" + "\n")
        for cfg, data in results.items():
            m = data['metrics']
            f.write(f"  {cfg} & {m['tp']} & {m['fp']} & {m['tn']} & {m['fn']} "
                    f"& {m['precision']:.4f} & {m['recall']:.4f} "
                    f"& {m['f1']:.4f} & {m['fpr']:.4f} \\\\\n")
        f.write(r"\bottomrule" + "\n")
        f.write(r"\end{tabular}" + "\n")
        f.write(r"\end{table}" + "\n")


if __name__ == '__main__':
    print("=" * 64)
    print("DFC-PV Ablation Study (31 samples, 4 configs)")
    print("=" * 64)
    run_ablation()
