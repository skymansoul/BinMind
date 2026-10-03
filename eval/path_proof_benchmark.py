"""
路径敏感约束传播 基准测试 — 对68个堆溢出样本运行 路径敏感约束传播 维度6,
与 仿射边界验证 baseline/enhanced 对比 TP/FP/TN/FN + Precision/Recall/F1.

路径敏感约束传播 独立检测逻辑:
  - 路径敏感约束传播 证明 OVERFLOW → detected=True
  - 路径敏感约束传播 证明 SAFE → detected=False (filtered)
  - 路径敏感约束传播 UNCERTAIN → 回退到 enhanced 仿射关系边界验证 判定
"""

from __future__ import annotations

import json, os, sys, time
from pathlib import Path
from typing import Dict, List, Tuple

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from eval.gapsbv_benchmark import (
    discover_heap_samples, read_source, extract_function_body,
    classify, compute_metrics,
)

sys.path.insert(0, os.path.join(BASE, 'tests'))
try:
    from collect_results import EXPECTED_MAP
except ImportError:
    EXPECTED_MAP = {}


def _get_expected(name: str) -> Tuple[str, bool]:
    if name in EXPECTED_MAP:
        return EXPECTED_MAP[name]
    for k, v in EXPECTED_MAP.items():
        if name in k or k in name:
            return v
    return ('heap-overflow', None)


def run_mivr_detect(pseudocode: str) -> Dict:
    """路径敏感约束传播 独立检测: 仅当 路径敏感约束传播 证明溢出或安全时给出判定。

    返回 {detected: bool, verdict: str, confidence: float, reason: str}
    """
    result = {'detected': False, 'verdict': 'UNCERTAIN',
              'confidence': 0.0, 'reason': ''}

    try:
        from analysis.path_proof_pipeline import detect_heap_overflow_mivr
        verdict, conf, proofs = detect_heap_overflow_mivr(pseudocode)
        result['verdict'] = verdict
        result['confidence'] = conf

        if verdict == 'OVERFLOW':
            result['detected'] = True
            result['reason'] = '; '.join(
                f"{p.proof_level}:{p.proof_detail[:80]}" for p in proofs
                if p.verdict == 'OVERFLOW')
        elif verdict == 'SAFE':
            result['detected'] = False
            result['reason'] = '; '.join(
                f"{p.proof_level}:{p.proof_detail[:80]}" for p in proofs
                if p.verdict == 'SAFE')
        else:
            result['reason'] = '; '.join(
                f"{p.proof_detail[:80]}" for p in proofs)
    except Exception as e:
        result['reason'] = f'Error: {e}'

    return result


def run_combined_detect(pseudocode: str) -> Dict:
    """组合检测: 路径敏感约束传播 优先, UNCERTAIN 时回退到 仿射关系边界验证 enhanced。

    策略:
      1. 路径敏感约束传播 SAFE → FILTER (不检出)
      2. 路径敏感约束传播 OVERFLOW → 检出
      3. 路径敏感约束传播 UNCERTAIN → 回退到 仿射边界验证 enhanced 判定
    """
    mivr = run_mivr_detect(pseudocode)

    if mivr['verdict'] == 'SAFE':
        return {'detected': False, 'verdict': 'SAFE',
                'confidence': mivr['confidence'],
                'reason': f'路径敏感约束传播-FILTER: {mivr["reason"]}',
                'source': '路径敏感约束传播'}
    elif mivr['verdict'] == 'OVERFLOW':
        return {'detected': True, 'verdict': 'OVERFLOW',
                'confidence': mivr['confidence'],
                'reason': f'路径敏感约束传播-DETECT: {mivr["reason"]}',
                'source': '路径敏感约束传播'}

    # UNCERTAIN — 回退到 enhanced 仿射边界验证
    try:
        from core.unified_heap_pipeline import analyze_heap_safety
        findings, stats = analyze_heap_safety(pseudocode, '', '')
        actionable = [f for f in findings
                      if f.get('verdict', '') in ('POSSIBLE', 'DEFINITE', 'CONFIRMED')
                      and f.get('severity', '') in ('Critical', 'High', 'Medium')]
        if actionable:
            return {'detected': True, 'verdict': actionable[0].get('verdict', 'POSSIBLE'),
                    'confidence': max(f.get('confidence', 0) for f in actionable),
                    'reason': f'GAPSBV-fallback: {actionable[0].get("description", "")}',
                    'source': 'GAPSBV'}
        else:
            return {'detected': False, 'verdict': 'FILTERED',
                    'confidence': 0.0,
                    'reason': 'GAPSBV-fallback: filtered',
                    'source': 'GAPSBV'}
    except Exception as e:
        return {'detected': False, 'verdict': 'ERROR',
                'confidence': 0.0, 'reason': str(e), 'source': 'ERROR'}


def run_benchmark():
    samples = discover_heap_samples()
    print(f'Discovered {len(samples)} heap overflow samples')

    mivr_results = []
    combined_results = []

    for i, s in enumerate(samples):
        code = read_source(s['source'])
        if not code:
            continue
        body = extract_function_body(code)
        vuln_type, should_detect = _get_expected(s['name'])
        if should_detect is None:
            continue

        # C 源码 → 伪代码
        try:
            from core.c_to_pseudocode import convert as c_to_pseudo
            pseudo_body = c_to_pseudo(code)
        except Exception:
            pseudo_body = body

        # 路径敏感约束传播 独立检测
        m_result = run_mivr_detect(pseudo_body)
        m_class = classify(should_detect, m_result['detected'])
        mivr_results.append({
            'name': s['name'], 'class': m_class,
            'detected': m_result['detected'], 'expected': should_detect,
            'verdict': m_result['verdict'],
            'confidence': m_result['confidence'],
        })

        # 组合检测 (路径敏感约束传播 + 仿射边界验证 fallback)
        c_result = run_combined_detect(pseudo_body)
        c_class = classify(should_detect, c_result['detected'])
        combined_results.append({
            'name': s['name'], 'class': c_class,
            'detected': c_result['detected'], 'expected': should_detect,
            'verdict': c_result['verdict'],
            'confidence': c_result['confidence'],
            'source': c_result.get('source', '?'),
        })

        if (i + 1) % 20 == 0:
            print(f'  processed {i + 1}/{len(samples)}...')

    m_metrics = compute_metrics(mivr_results)
    c_metrics = compute_metrics(combined_results)

    # 加载现有基线
    prev_path = os.path.join(BASE, 'eval', 'gapsbv_benchmark_results.json')
    prev_baseline = None
    prev_enhanced = None
    if os.path.exists(prev_path):
        with open(prev_path, 'r') as f:
            prev = json.load(f)
            prev_baseline = prev.get('baseline', {})
            prev_enhanced = prev.get('enhanced', {})

    output = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'sample_count': len(samples),
        'evaluated_samples': len(mivr_results),
        'mivr_standalone': m_metrics,
        'mivr_combined': c_metrics,
        'previous_baseline': prev_baseline,
        'previous_enhanced': prev_enhanced,
        'details': {
            'mivr': mivr_results,
            'combined': combined_results,
        },
    }

    out_path = os.path.join(BASE, 'eval', 'mivr_benchmark_results.json')
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    # 打印对比摘要
    sep = '-' * 72
    print(f'\n{"="*72}')
    print(f'MIVR Benchmark Results ({len(mivr_results)} samples)')
    print(f'{"="*72}')
    header = f'{"Metric":<20} {"Baseline":>10} {"GAPSBV":>10} {"MIVR":>10} {"MIVR+":>10}'
    print(header)
    print(sep)

    for key, label in [('precision','Precision'), ('recall','Recall'),
                        ('f1','F1 Score'), ('fp_rate','FP Rate')]:
        bv = prev_baseline.get(key, 0) if prev_baseline else 0
        ev = prev_enhanced.get(key, 0) if prev_enhanced else 0
        mv = m_metrics[key]
        cv = c_metrics[key]
        print(f'{label:<20} {bv:>9.4f} {ev:>9.4f} {mv:>9.4f} {cv:>9.4f}')
    print(sep)
    print(f'{"TP":<20} {prev_baseline.get("TP","?"):>9} {prev_enhanced.get("TP","?"):>9} {m_metrics["TP"]:>9} {c_metrics["TP"]:>9}')
    print(f'{"FP":<20} {prev_baseline.get("FP","?"):>9} {prev_enhanced.get("FP","?"):>9} {m_metrics["FP"]:>9} {c_metrics["FP"]:>9}')
    print(f'{"FN":<20} {prev_baseline.get("FN","?"):>9} {prev_enhanced.get("FN","?"):>9} {m_metrics["FN"]:>9} {c_metrics["FN"]:>9}')
    print(f'{"TN":<20} {prev_baseline.get("TN","?"):>9} {prev_enhanced.get("TN","?"):>9} {m_metrics["TN"]:>9} {c_metrics["TN"]:>9}')
    print(sep)

    # FP 削减率
    if prev_enhanced and prev_enhanced.get('FP', 0) > 0:
        fp_red = (prev_enhanced['FP'] - c_metrics['FP']) / prev_enhanced['FP'] * 100
        print(f'FP Reduction vs GAPSBV enhanced: {fp_red:.1f}%')
    if prev_baseline and prev_baseline.get('FP', 0) > 0:
        fp_red_b = (prev_baseline['FP'] - c_metrics['FP']) / prev_baseline['FP'] * 100
        print(f'FP Reduction vs baseline: {fp_red_b:.1f}%')

    print(f'\nResults written to: {out_path}')

    # 打印路径敏感约束传播特有的 FILTER 详情
    mivr_filtered = [r for r in mivr_results if r['verdict'] == 'SAFE']
    mivr_detected = [r for r in mivr_results if r['verdict'] == 'OVERFLOW']
    print(f'\nMIVR standalone: {len(mivr_detected)} OVERFLOW, {len(mivr_filtered)} SAFE (filtered)')

    return output


if __name__ == '__main__':
    run_benchmark()
