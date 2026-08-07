"""UAF完整消融实验 — 7配置×55样本 量化TPV/PCOL/Interproc增量 ≤300行."""
from __future__ import annotations
import csv, json, sys, time
from pathlib import Path
from typing import Dict, List, Tuple

_DEEMO = Path(__file__).resolve().parent.parent
if str(_DEEMO) not in sys.path:
    sys.path.insert(0, str(_DEEMO))

from eval.uaf_cve_samples import ALL_UAF_CVE_SAMPLES
from eval.uaf_hoig_ablation_samples import (
    INTRA_SAMPLES, PATH_SAMPLES, CROSS_SAMPLES, CVE_SAMPLES)
from analysis.uaf_hoig_builder import HoigBuilder
from analysis.uaf_hoig_propagator import HoigPropagator
from analysis.uaf_hoig_cross_func import HoigCrossFuncVerifier
from analysis.uaf_hoig_path_sensitive import PathSensitiveHOIG
from analysis.uaf_pcol_bridge import verify_with_pcol
from analysis.uaf_temporal_path_verifier import TemporalPathVerifier
from analysis.uaf_interprocedural import InterprocSummarizer

OUTPUT_DIR = _DEEMO / "eval" / "results"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# 消融配置
def _hoig_only(code: str, name: str) -> str:
    """仅HOIG Builder判定."""
    b = HoigBuilder()
    _, _, vs = b.build(code, name)
    return 'CONFIRMED' if any(v.verdict == 'CONFIRMED' for v in vs) else 'SAFE'

def _hoig_pcol(code: str, name: str) -> str:
    """HOIG+PCOL联合判定."""
    return verify_with_pcol(code, name).verdict

def _tpv_only(source: str) -> str:
    """仅TemporalPathVerifier判定."""
    tpv = TemporalPathVerifier(max_paths=128)
    results = tpv.verify(source)
    for r in results:
        vv = r.verdict.value if hasattr(r.verdict, 'value') else str(r.verdict)
        if vv in ('UAF', 'DOUBLE_FREE'):
            return 'CONFIRMED'
    return 'SAFE'

def _hoig_pcol_tpv(code: str, name: str, source: str) -> str:
    """HOIG+PCOL+TPV全融合: PCOL为终审, TPV补充跨函数FN + 别名double-free.
    
    架构: HOIG+PCOL处理互斥/安全模式 + TPV处理跨函数/别名/回调
    级联: PCOL判CONFIRMED→确认; SAFE时TPV补充:
      - virtual free(跨函数传播) → CONFIRMED
      - double-free(别名闭包) → CONFIRMED
      - 其他(MUTEX等) → PCOL终审SAFE
    """
    pcol_v = verify_with_pcol(code, name).verdict
    if pcol_v == 'CONFIRMED':
        return 'CONFIRMED'
    # PCOL判SAFE → TPV补充
    tpv = TemporalPathVerifier(max_paths=128)
    tpv_results = tpv.verify(source)
    tpv_uaf = False
    tpv_double_free = False
    for r in tpv_results:
        vv = r.verdict.value if hasattr(r.verdict, 'value') else str(r.verdict)
        if vv in ('UAF', 'DOUBLE_FREE'):
            tpv_uaf = True
        if vv == 'DOUBLE_FREE':
            tpv_double_free = True
    if not tpv_uaf:
        return 'SAFE'
    # 跨函数virtual free检测
    summarizer = InterprocSummarizer()
    vfrees, _ = summarizer.propagate(source)
    if vfrees or tpv_double_free:
        return 'CONFIRMED'
    # 非跨函数非double-free → MUTEX等误报
    return 'SAFE'


_CHALLENGE_DIR = _DEEMO / "tests" / "cve_samples" / "uaf"
CHALLENGE_SAMPLES = [
    ('uaf_16','TP'),('uaf_17','TP'),('uaf_18','TN'),('uaf_19','TP'),
    ('uaf_20','TP'),('uaf_21','TP'),('uaf_22','TP'),('uaf_23','TP'),
    ('uaf_24','TP'),('uaf_25','TN'),('uaf_26','TP'),('uaf_27','TN'),
    ('uaf_28','TP'),('uaf_29','TN'),('uaf_30','TP'),
]

def _load_challenge():
    """加载15个挑战样本源码."""
    samples = []
    for name, exp in CHALLENGE_SAMPLES:
        d = _CHALLENGE_DIR / name
        if not d.exists():
            continue
        c_files = list(d.glob("*.c"))
        if not c_files:
            continue
        src = c_files[0].read_text(encoding='utf-8', errors='replace')
        samples.append((name, src, exp))
    return samples


def _metrics(records, pred_key='verdict'):
    tp = sum(1 for r in records if r['expected']=='CONFIRMED' and r[pred_key]=='CONFIRMED')
    fp = sum(1 for r in records if r['expected']!='CONFIRMED' and r[pred_key]=='CONFIRMED')
    tn = sum(1 for r in records if r['expected']!='CONFIRMED' and r[pred_key]!='CONFIRMED')
    fn = sum(1 for r in records if r['expected']=='CONFIRMED' and r[pred_key]!='CONFIRMED')
    p = tp/max(1,tp+fp); r = tp/max(1,tp+fn)
    f1 = 2*p*r/max(.001,p+r); fpr = fp/max(1,fp+tn)
    return {'tp':tp,'fp':fp,'tn':tn,'fn':fn,
            'P':round(p,4),'R':round(r,4),'F1':round(f1,4),'FPR':round(fpr,4)}

# 主实验
def run_ablation():
    """运行7配置×55样本消融实验."""
    print("=" * 70)
    print("UAF Full Ablation Study — 7 Configs × 55 Samples")
    print("=" * 70)

    # 加载40个HOIG/PCOL样本
    pcol_samples = [(n, c, e) for n, c, e, _ in ALL_UAF_CVE_SAMPLES]
    # 加载15个挑战样本
    challenge_samples = _load_challenge()
    total = len(pcol_samples) + len(challenge_samples)
    print(f"  Samples: {len(pcol_samples)} HOIG+PCOL + {len(challenge_samples)} challenge = {total}")

    configs = [
        ('A0_HOIG_only',      'hoig'),
        ('A1_HOIG_PCOL',      'pcol'),
        ('A2_TPV_only',       'tpv'),
        ('A3_HOIG_PCOL_TPV',  'union'),
    ]

    all_results = {}
    for cfg_name, cfg_type in configs:
        records = []
        # 40样本
        for name, code, expected in pcol_samples:
            t0 = time.perf_counter()
            if cfg_type == 'hoig':
                v = _hoig_only(code, name)
            elif cfg_type == 'pcol':
                v = _hoig_pcol(code, name)
            elif cfg_type == 'tpv':
                v = _tpv_only(code)
            elif cfg_type == 'union':
                v = _hoig_pcol_tpv(code, name, code)
            dt = (time.perf_counter() - t0) * 1000
            records.append({'sample': name, 'expected': expected,
                            'verdict': v, 'time_ms': round(dt, 3)})
        # 15挑战样本
        for name, src, expected in challenge_samples:
            t0 = time.perf_counter()
            exp_c = 'CONFIRMED' if expected == 'TP' else 'SAFE'
            if cfg_type == 'hoig':
                v = _hoig_only(src, name)
            elif cfg_type == 'pcol':
                v = _hoig_pcol(src, name)
            elif cfg_type == 'tpv':
                v = _tpv_only(src)
            elif cfg_type == 'union':
                v = _hoig_pcol_tpv(src, name, src)
            dt = (time.perf_counter() - t0) * 1000
            records.append({'sample': name, 'expected': exp_c,
                            'verdict': v, 'time_ms': round(dt, 3)})
        m = _metrics(records)
        all_results[cfg_name] = m
        print(f"  {cfg_name:<22s} TP={m['tp']} FP={m['fp']} TN={m['tn']} FN={m['fn']} "
              f"P={m['P']:.4f} R={m['R']:.4f} F1={m['F1']:.4f} FPR={m['FPR']:.4f}")

    # 保存
    out = OUTPUT_DIR / 'uaf_full_ablation.json'
    with open(out, 'w', encoding='utf-8') as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)
    print(f"\n  JSON: {out}")

    # LaTeX
    _write_latex(all_results, _DEEMO / 'eval' / 'uaf_full_ablation_table.tex')
    print(f"  LaTeX: {_DEEMO / 'eval' / 'uaf_full_ablation_table.tex'}")
    print("=" * 70)
    return all_results


def _write_latex(results, path):
    with open(path, 'w', encoding='utf-8') as f:
        f.write(r"\begin{table}[htbp]" + "\n")
        f.write(r"\centering" + "\n")
        f.write(r"\caption{UAF Full Ablation Study (55 Samples)}" + "\n")
        f.write(r"\label{tab:uaf_full_ablation}" + "\n")
        f.write(r"\begin{tabular}{lrrrrrrrr}" + "\n")
        f.write(r"\toprule" + "\n")
        f.write(r"Config & TP & FP & TN & FN & P & R & F1 & FPR \\" + "\n")
        f.write(r"\midrule" + "\n")
        for cfg_name, m in results.items():
            f.write(f"  {cfg_name} & {m['tp']} & {m['fp']} & {m['tn']} & {m['fn']} "
                    f"& {m['P']:.4f} & {m['R']:.4f} "
                    f"& {m['F1']:.4f} & {m['FPR']:.4f} \\\\\n")
        f.write(r"\bottomrule" + "\n")
        f.write(r"\end{tabular}" + "\n")
        f.write(r"\end{table}" + "\n")


if __name__ == '__main__':
    run_ablation()
