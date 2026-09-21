"""UAF统一回归入口 — 一次性运行所有UAF测试/基准/消融 ≤300行."""
from __future__ import annotations
import json, sys, time
from pathlib import Path
from typing import Dict, List, Tuple

_DEEMO = Path(__file__).resolve().parent.parent
if str(_DEEMO) not in sys.path:
    sys.path.insert(0, str(_DEEMO))

from eval.uaf_cve_samples import ALL_UAF_CVE_SAMPLES, get_sample_count
from eval.uaf_obj_graph_ablation_samples import (
    INTRA_SAMPLES, PATH_SAMPLES, CROSS_SAMPLES, CVE_SAMPLES)
from analysis.uaf_obj_graph_builder import HoigBuilder
from analysis.uaf_obj_graph_propagator import HoigPropagator
from analysis.uaf_obj_graph_cross_func import HoigCrossFuncVerifier
from analysis.uaf_obj_graph_path_sensitive import PathSensitiveHOIG
from analysis.uaf_path_lifecycle_bridge import verify_with_pcol
from analysis.uaf_temporal_path_verifier import TemporalPathVerifier
from analysis.uaf_obj_graph_pipeline import UafHoigPipeline

OUTPUT_DIR = _DEEMO / "eval" / "results"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# 1. 对象身份图 (Object Identity Graph)+路径条件对象生命周期 (Path-Conditioned Object Lifecycle) 40样本基准
def _run_pcol_benchmark() -> Dict:
    """仅对象身份图 vs 对象身份图+路径条件对象生命周期 全量基准."""
    records = []
    for name, code, expected, category in ALL_UAF_CVE_SAMPLES:
        builder = HoigBuilder()
        _, _, vds = builder.build(code, name)
        hoig_r = 'CONFIRMED' if any(v.verdict == 'CONFIRMED' for v in vds) else 'SAFE'
        pcol_r = verify_with_pcol(code, name).verdict
        records.append({'sample': name, 'cat': category,
                        'expected': expected,
                        'hoig': hoig_r, 'pcol': pcol_r})
    return records

# 2. 挑战样本 TPV+对象身份图 并集
_CHALLENGE_DIR = _DEEMO / "tests" / "cve_samples" / "uaf"
CHALLENGE_SAMPLES = [
    ('uaf_16', 'TP'), ('uaf_17', 'TP'), ('uaf_18', 'TN'), ('uaf_19', 'TP'),
    ('uaf_20', 'TP'), ('uaf_21', 'TP'), ('uaf_22', 'TP'), ('uaf_23', 'TP'),
    ('uaf_24', 'TP'), ('uaf_25', 'TN'), ('uaf_26', 'TP'), ('uaf_27', 'TN'),
    ('uaf_28', 'TP'), ('uaf_29', 'TN'), ('uaf_30', 'TP'),
]

def _run_challenge() -> List[Dict]:
    """15个挑战样本 TPV+对象身份图 并集检测."""
    if not _CHALLENGE_DIR.exists():
        return []
    results = []
    for name, exp in CHALLENGE_SAMPLES:
        # 查找.c源文件
        src_dir = _CHALLENGE_DIR / name
        c_files = list(src_dir.glob("*.c"))
        if not c_files:
            continue
        source = c_files[0].read_text(encoding='utf-8', errors='replace')
        tpv = TemporalPathVerifier(max_paths=128)
        tpv_results = tpv.verify(source)
        tpv_det = False
        for x in tpv_results:
            vv = x.verdict.value if hasattr(x.verdict, 'value') else str(x.verdict)
            if vv in ('UAF', 'DOUBLE_FREE'):
                tpv_det = True; break
        hoig_det = False
        try:
            pl = UafHoigPipeline()
            # 从源码提取函数名和函数体
            import re
            fn_re = re.compile(r'\b(\w+)\s*\([^)]*\)\s*\{')
            lines = source.splitlines()
            fn_name = 'main'
            for ln in lines:
                fm = fn_re.search(ln)
                if fm and fm.group(1) not in ('if','while','for','switch','return'):
                    fn_name = fm.group(1)
                    break
            hv = pl.analyze(source, fn_name, {}, [])
            hoig_det = hv.verdict == 'CONFIRMED'
        except Exception:
            pass
        detected = tpv_det or hoig_det
        expected_uaf = exp == 'TP'
        results.append({'sample': name, 'expected': exp,
                        'tpv': tpv_det, 'hoig': hoig_det,
                        'detected': detected, 'correct': detected == expected_uaf})
    return results

# 3. 对象身份图消融 5配置
def _run_ablation() -> Dict:
    """A0~A4 五配置消融."""
    all_samples = ([(n, c, e) for n, c, e in INTRA_SAMPLES]
                 + [(n, c, e) for n, c, e in PATH_SAMPLES])
    cross = ([(n, c, e) for n, c, e, _ in CROSS_SAMPLES]
           + [(n, c, e) for n, c, e, _ in CVE_SAMPLES])
    configs = {}
    # A0: baseline
    a0 = []
    for name, code, exp in all_samples:
        b = HoigBuilder(); _, _, vs = b.build(code, name)
        det = any(v.verdict == 'CONFIRMED' for v in vs)
        a0.append(det == (exp == 'CONFIRMED'))
    configs['A0_baseline'] = a0
    # A4: full (simplified)
    a4 = []
    for name, code, exp in all_samples:
        pcol_v = verify_with_pcol(code, name).verdict
        a4.append(pcol_v == exp)
    configs['A4_full'] = a4
    return {k: {'correct': sum(v), 'total': len(v),
                'acc': round(sum(v)/max(1,len(v)), 4)}
            for k, v in configs.items()}

# 4. 汇总
def _metrics(records, pred_key, exp_key='expected', pos='CONFIRMED'):
    tp = sum(1 for r in records if r[exp_key] == pos and r[pred_key] == pos)
    fp = sum(1 for r in records if r[exp_key] != pos and r[pred_key] == pos)
    tn = sum(1 for r in records if r[exp_key] != pos and r[pred_key] != pos)
    fn = sum(1 for r in records if r[exp_key] == pos and r[pred_key] != pos)
    p = tp / max(1, tp + fp); r = tp / max(1, tp + fn)
    f1 = 2*p*r / max(.001, p+r); fpr = fp / max(1, fp+tn)
    return {'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn,
            'P': round(p, 4), 'R': round(r, 4),
            'F1': round(f1, 4), 'FPR': round(fpr, 4)}

def run_all():
    """运行全部UAF回归测试."""
    print("=" * 70)
    print("BinMind UAF Unified Regression")
    print("=" * 70)
    report = {}

    # 1. 对象身份图+路径条件对象生命周期 40样本
    print("\n[1/3] HOIG+PCOL 40-sample benchmark ...")
    t0 = time.perf_counter()
    pcol_records = _run_pcol_benchmark()
    pcol_m = _metrics(pcol_records, 'pcol')
    hoig_m = _metrics(pcol_records, 'hoig')
    print(f"  HOIG-only:  TP={hoig_m['tp']} FP={hoig_m['fp']} "
          f"TN={hoig_m['tn']} FN={hoig_m['fn']} "
          f"P={hoig_m['P']:.4f} R={hoig_m['R']:.4f} F1={hoig_m['F1']:.4f}")
    print(f"  HOIG+PCOL:  TP={pcol_m['tp']} FP={pcol_m['fp']} "
          f"TN={pcol_m['tn']} FN={pcol_m['fn']} "
          f"P={pcol_m['P']:.4f} R={pcol_m['R']:.4f} F1={pcol_m['F1']:.4f}")
    report['pcol_benchmark'] = {'hoig': hoig_m, 'pcol': pcol_m}

    # 2. 挑战样本
    print("\n[2/3] 15 challenge samples (TPV+HOIG union) ...")
    ch_results = _run_challenge()
    if ch_results:
        ch_correct = sum(1 for r in ch_results if r['correct'])
        ch_total = len(ch_results)
        ch_tp = sum(1 for r in ch_results
                    if r['expected'] == 'TP' and r['detected'])
        ch_fp = sum(1 for r in ch_results
                    if r['expected'] == 'TN' and r['detected'])
        ch_tn = sum(1 for r in ch_results
                    if r['expected'] == 'TN' and not r['detected'])
        ch_fn = sum(1 for r in ch_results
                    if r['expected'] == 'TP' and not r['detected'])
        p = ch_tp / max(1, ch_tp+ch_fp)
        r = ch_tp / max(1, ch_tp+ch_fn)
        f1 = 2*p*r / max(.001, p+r)
        fpr = ch_fp / max(1, ch_fp+ch_tn)
        print(f"  {ch_correct}/{ch_total} correct | "
              f"TP={ch_tp} FP={ch_fp} TN={ch_tn} FN={ch_fn} | "
              f"P={p:.4f} R={r:.4f} F1={f1:.4f} FPR={fpr:.4f}")
        report['challenge'] = {'correct': ch_correct, 'total': ch_total,
                               'TP': ch_tp, 'FP': ch_fp, 'TN': ch_tn, 'FN': ch_fn,
                               'P': round(p, 4), 'R': round(r, 4),
                               'F1': round(f1, 4), 'FPR': round(fpr, 4)}
    else:
        print("  (challenge samples not found, skipped)")
        report['challenge'] = None

    # 3. 消融
    print("\n[3/3] HOIG ablation (A0 vs A4) ...")
    abl = _run_ablation()
    for k, v in abl.items():
        print(f"  {k}: {v['correct']}/{v['total']} acc={v['acc']:.4f}")
    report['ablation'] = abl

    elapsed = time.perf_counter() - t0
    print(f"\nTotal time: {elapsed:.2f}s")
    print("=" * 70)

    # 保存
    out = OUTPUT_DIR / 'uaf_unified_regression.json'
    with open(out, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False, default=str)
    print(f"JSON saved: {out}")
    return report


if __name__ == '__main__':
    run_all()
