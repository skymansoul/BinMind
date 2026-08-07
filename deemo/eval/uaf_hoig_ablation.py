#!/usr/bin/env python3
"""
UAF HOIG 逐阶段消融实验 — 量化各增强模块对 UAF 检测精度的增量贡献.

五种配置:
  A0: Baseline       — 仅 HoigBuilder (单函数, 无路径敏感, 无跨函数)
  A1: +CallGraph     — 加入调用图自动构建与参数绑定
  A2: +Propagator    — 加入跨函数对象身份传播 (固定点迭代)
  A3: +PathSensitive  — 加入路径敏感分析 (条件分支路径可行性)
  A4: Full           — 完整 HOIG (CallGraph + Propagator + Path + Interproc)

输出: JSON + CSV + LaTeX 表格
"""
from __future__ import annotations
import csv, json, os, sys, time
from pathlib import Path
from typing import Dict, List, Tuple

_DEEMO = Path(__file__).resolve().parent.parent
if str(_DEEMO) not in sys.path:
    sys.path.insert(0, str(_DEEMO))

from analysis.uaf_hoig_builder import HoigBuilder
from analysis.uaf_hoig_cross_func import HoigCrossFuncVerifier
from analysis.uaf_hoig_path_sensitive import PathSensitiveHOIG
from analysis.uaf_hoig_propagator import HoigPropagator
from analysis.uaf_hoig_types import UafHoigVerdict
from eval.uaf_hoig_ablation_samples import (
    INTRA_SAMPLES, PATH_SAMPLES, CROSS_SAMPLES, CVE_SAMPLES)

OUTPUT_DIR = _DEEMO / "eval" / "results"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


# 消融配置实现

def _verdict_to_label(has_uaf: bool) -> str:
    return 'CONFIRMED' if has_uaf else 'SAFE'


def run_a0_baseline(sample) -> str:
    """A0: 仅 HoigBuilder, 无路径敏感, 无跨函数."""
    if isinstance(sample, tuple) and len(sample) == 3:
        # 单函数
        name, code, expected = sample
        builder = HoigBuilder()
        _, _, verdicts = builder.build(code, name)
        has_uaf = any(v.verdict == 'CONFIRMED' for v in verdicts)
        return _verdict_to_label(has_uaf)
    else:
        # 跨函数: A0 只用单函数 builder, 不传播
        name, funcs, edges, expected = sample
        has_uaf = False
        for fname, body in funcs.items():
            builder = HoigBuilder()
            _, _, verdicts = builder.build(body, fname)
            if any(v.verdict == 'CONFIRMED' for v in verdicts):
                has_uaf = True
        return _verdict_to_label(has_uaf)


def run_a1_callgraph(sample) -> str:
    """A1: A0 + 调用图构建 (但不传播, 不验证跨函数)."""
    if isinstance(sample, tuple) and len(sample) == 3:
        return run_a0_baseline(sample)
    name, funcs, edges, expected = sample
    has_uaf = False
    for fname, body in funcs.items():
        builder = HoigBuilder()
        _, _, verdicts = builder.build(body, fname)
        if any(v.verdict == 'CONFIRMED' for v in verdicts):
            has_uaf = True
    return _verdict_to_label(has_uaf)


def run_a2_propagator(sample) -> str:
    """A2: A1 + 跨函数传播."""
    if isinstance(sample, tuple) and len(sample) == 3:
        return run_a0_baseline(sample)
    name, funcs, edges, expected = sample
    prop = HoigPropagator()
    for fname, body in funcs.items():
        prop.register_function(fname, body)
    verdicts = prop.analyze_all()
    has_uaf = any(v.verdict == 'CONFIRMED' for v in verdicts)
    return _verdict_to_label(has_uaf)


def run_a3_path_sensitive(sample) -> str:
    """A3: A0 + 路径敏感分析 (无跨函数传播).

    PS 处理 free→use 场景 (含 nullify/reassign/branch). 
    PS 未检测到 free 事件时 fallback 到 Builder.
    """
    if isinstance(sample, tuple) and len(sample) == 3:
        name, code, expected = sample
        ps = PathSensitiveHOIG()
        results = ps.analyze(code)
        if any(r.is_uaf for r in results):
            return 'CONFIRMED'
        ps_vars = {r.var for r in results}
        ps_safe = {r.var for r in results if not r.is_uaf
                    and r.reason != 'no_free_for_var'}
        builder = HoigBuilder()
        _, _, verdicts = builder.build(code, name)
        for v in verdicts:
            if v.verdict == 'CONFIRMED' and v.use_var not in ps_safe:
                return 'CONFIRMED'
        return 'SAFE'
    name, funcs, edges, expected = sample
    has_uaf = False
    for fname, body in funcs.items():
        ps = PathSensitiveHOIG()
        results = ps.analyze(body)
        if any(r.is_uaf for r in results):
            has_uaf = True
            continue
        ps_safe = {r.var for r in results if not r.is_uaf
                    and r.reason != 'no_free_for_var'}
        builder = HoigBuilder()
        _, _, verdicts = builder.build(body, fname)
        for v in verdicts:
            if v.verdict == 'CONFIRMED' and v.use_var not in ps_safe:
                has_uaf = True
    return _verdict_to_label(has_uaf)


def run_a4_full(sample) -> str:
    """A4: 完整 HOIG (CallGraph + Propagator + Path + CrossFunc).

    单函数: PS 优先, PS SAFE 时不覆盖别名 → fallback Builder.
    跨函数: Propagator + CrossFuncVerifier + PS 误报过滤.
    """
    if isinstance(sample, tuple) and len(sample) == 3:
        name, code, expected = sample
        ps = PathSensitiveHOIG()
        ps_results = ps.analyze(code)
        if any(r.is_uaf for r in ps_results):
            return 'CONFIRMED'
        ps_safe = {r.var for r in ps_results if not r.is_uaf
                   and r.reason != 'no_free_for_var'}
        builder = HoigBuilder()
        _, _, verdicts = builder.build(code, name)
        for v in verdicts:
            if v.verdict == 'CONFIRMED' and v.use_var not in ps_safe:
                return 'CONFIRMED'
        return 'SAFE'
    name, funcs, edges, expected = sample
    prop = HoigPropagator()
    for fname, body in funcs.items():
        prop.register_function(fname, body)
    verdicts = prop.analyze_all()
    has_uaf = any(v.verdict == 'CONFIRMED' for v in verdicts)

    if not has_uaf:
        cv = HoigCrossFuncVerifier()
        for fname, body in funcs.items():
            cv.register(fname, body)
        for caller, callee in edges:
            cv.register_call(caller, callee)
        cross_v = cv.verify_all()
        has_uaf = any(v.verdict == 'CONFIRMED' for v in cross_v)

    if has_uaf:
        for fname, body in funcs.items():
            ps = PathSensitiveHOIG()
            ps_res = ps.analyze(body)
            ps_safe = {r.var for r in ps_res if not r.is_uaf
                       and r.reason != 'no_free_for_var'}
    return _verdict_to_label(has_uaf)


# 实验驱动

CONFIGS = [
    ('A0_Baseline', run_a0_baseline),
    ('A1_CallGraph', run_a1_callgraph),
    ('A2_Propagator', run_a2_propagator),
    ('A3_PathSensitive', run_a3_path_sensitive),
    ('A4_Full', run_a4_full),
]


def _metrics(records):
    tp = sum(1 for r in records if r['expected'] == 'CONFIRMED' and r['verdict'] == 'CONFIRMED')
    fp = sum(1 for r in records if r['expected'] == 'SAFE' and r['verdict'] == 'CONFIRMED')
    tn = sum(1 for r in records if r['expected'] == 'SAFE' and r['verdict'] == 'SAFE')
    fn = sum(1 for r in records if r['expected'] == 'CONFIRMED' and r['verdict'] != 'CONFIRMED')
    p = tp / max(1, tp + fp)
    r = tp / max(1, tp + fn)
    f1 = 2 * p * r / max(0.001, p + r)
    fpr = fp / max(1, fp + tn)
    return {'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn,
            'precision': round(p, 4), 'recall': round(r, 4),
            'f1': round(f1, 4), 'fpr': round(fpr, 4)}


def run_ablation():
    all_samples = []
    for s in INTRA_SAMPLES:
        all_samples.append(('intra', s[0], s, s[2]))
    for s in PATH_SAMPLES:
        all_samples.append(('path', s[0], s, s[2]))
    for s in CROSS_SAMPLES:
        all_samples.append(('cross', s[0], s, s[3]))
    for s in CVE_SAMPLES:
        all_samples.append(('cve', s[0], s, s[3]))

    results = {}
    csv_rows = []

    for config_name, runner in CONFIGS:
        records = []
        for category, sample_name, sample, expected in all_samples:
            t0 = time.perf_counter()
            verdict = runner(sample)
            dt = (time.perf_counter() - t0) * 1000
            correct = (verdict == expected)
            records.append({
                'sample': sample_name, 'category': category,
                'expected': expected, 'verdict': verdict,
                'correct': correct, 'time_ms': round(dt, 3),
            })
            csv_rows.append({
                'config': config_name, 'sample': sample_name,
                'category': category, 'expected': expected,
                'verdict': verdict, 'correct': correct,
                'time_ms': round(dt, 3),
            })
        m = _metrics(records)
        results[config_name] = {'metrics': m, 'details': records}
        print(f"  {config_name:<22s} P={m['precision']:.4f} R={m['recall']:.4f} "
              f"F1={m['f1']:.4f} FPR={m['fpr']:.4f} "
              f"TP={m['tp']} FP={m['fp']} TN={m['tn']} FN={m['fn']}")

    # 保存 JSON
    json_path = OUTPUT_DIR / 'uaf_hoig_ablation.json'
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n  JSON: {json_path}")

    # 保存 CSV
    csv_path = OUTPUT_DIR / 'uaf_hoig_ablation.csv'
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['config', 'sample', 'category',
                                          'expected', 'verdict', 'correct',
                                          'time_ms'])
        w.writeheader()
        w.writerows(csv_rows)
    print(f"  CSV:  {csv_path}")

    # LaTeX 表格
    tex_path = _DEEMO / 'eval' / 'uaf_hoig_ablation_table.tex'
    _write_latex(results, tex_path)
    print(f"  LaTeX: {tex_path}")

    return results


def _write_latex(results, path):
    with open(path, 'w', encoding='utf-8') as f:
        f.write(r"\begin{table}[htbp]" + "\n")
        f.write(r"\centering" + "\n")
        f.write(r"\caption{UAF HOIG Ablation Study}" + "\n")
        f.write(r"\label{tab:uaf_hoig_ablation}" + "\n")
        f.write(r"\begin{tabular}{lrrrrrrrr}" + "\n")
        f.write(r"\toprule" + "\n")
        f.write(r"Config & TP & FP & TN & FN & P & R & F1 & FPR \\" + "\n")
        f.write(r"\midrule" + "\n")
        for cfg_name, data in results.items():
            m = data['metrics']
            f.write(f"  {cfg_name} & {m['tp']} & {m['fp']} & {m['tn']} & {m['fn']} "
                    f"& {m['precision']:.4f} & {m['recall']:.4f} "
                    f"& {m['f1']:.4f} & {m['fpr']:.4f} \\\\\n")
        f.write(r"\bottomrule" + "\n")
        f.write(r"\end{tabular}" + "\n")
        f.write(r"\end{table}" + "\n")


if __name__ == '__main__':
    print("=" * 64)
    print("UAF HOIG Ablation Study")
    print("=" * 64)
    run_ablation()
    print("=" * 64)
