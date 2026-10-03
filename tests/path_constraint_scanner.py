"""
路径约束收集验证增强扫描器 — 将路径约束收集验证约束传播验证器集成到格式串检测管线.

检测管线:
  1. 路径约束收集验证从源码收集四类约束(Sink/Taint/Sanitize/CrossFunc)并求解安全标签
  2. 路径可行性检查对路径约束收集验证的VULN判定做路径条件过滤(消除路径不可达FP)
  3. 路径约束收集验证+路径可行性检查判定VULN → CONFIRMED
  4. 路径约束收集验证判定SAFE → FILTERED
  5. 路径约束收集验证判定UNCERTAIN → 回退到EnhancedFmtDetector(IR级)

与旧scanner(run_fmt_scanner.py)的区别:
  旧scanner仅用EnhancedFmtDetector(IR级), 无法判定snprintf %s透传等场景
  本扫描器以路径约束收集验证(源码级)为主检测器, 通过规则9正确判定间接传播漏洞

保守性:
  路径约束收集验证和路径可行性检查仅在能明确证明SAFE时过滤, 不引入假阴性
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from core.source_ir_extractor import extract_from_file as extract_ir
from core.format_string_enhanced import EnhancedFmtDetector
from core.path_constraint_pipeline import fcpv_filter
from core.path_feasibility_verifier import filter_fmt_by_pcfc
from core.path_constraint_constraint_types import SafetyLabel

FMT_GROUND_TRUTH: Dict[str, str] = {
    'sample_fmt_01': 'TP',
    'sample_fmt_02': 'FP',
    'sample_fmt_03': 'TP',
    'sample_fmt_04': 'TP',
    'sample_fmt_05': 'TP',
    'sample_fmt_06': 'FP',
    'sample_fmt_07': 'TP',
    'sample_fmt_08': 'TP',
    'sample_fmt_09': 'FP',
    'sample_fmt_10': 'TP',
    'sample_fmt_11': 'TP',
    'sample_fmt_12': 'TP',
    'sample_fmt_13': 'TP',
    'sample_fmt_14': 'TP',
    'sample_fmt_15': 'TP',
}

SAMPLES_DIR = os.path.join(PROJECT_DIR, 'samples', 'format_string')
OUTPUT_DIR = os.path.join(PROJECT_DIR, 'eval')


def run_sample_enhanced(sample_dir: str) -> Dict[str, Any]:
    """路径约束收集验证增强检测: 路径约束收集验证+路径可行性检查为主, EnhancedFmtDetector为UNCERTAIN回退."""
    label = FMT_GROUND_TRUTH.get(sample_dir, 'TP')
    full_dir = os.path.join(SAMPLES_DIR, sample_dir)
    c_files = list(Path(full_dir).glob('*.c'))
    if not c_files:
        return _err_result(sample_dir, label, 'No C source found')

    c_file = str(c_files[0])
    t0 = time.time()
    source = Path(c_file).read_text(encoding='utf-8', errors='replace')

    fcpv_result = fcpv_filter(source)
    fcpv_vuln = fcpv_result.get('vuln', [])
    fcpv_safe = fcpv_result.get('safe', [])
    fcpv_uncertain = fcpv_result.get('uncertain', [])

    if fcpv_vuln:
        try:
            pcfc_candidates, pcfc_stats = filter_fmt_by_pcfc(
                source, fcpv_vuln)
        except Exception:
            pcfc_candidates = fcpv_vuln
            pcfc_stats = {'pcfc_filtered': 0}
    else:
        pcfc_candidates = []
        pcfc_stats = {'pcfc_filtered': 0}

    remaining_vuln = [
        c for c in pcfc_candidates if c.label == SafetyLabel.VULN
    ]
    pcfc_filtered_count = len(fcpv_vuln) - len(remaining_vuln)

    if remaining_vuln:
        result_verdict = 'CONFIRMED'
        result_conf = max(c.confidence for c in remaining_vuln)
    elif fcpv_uncertain:
        result_verdict, result_conf = _fallback_to_enhanced(c_file)
    elif fcpv_safe:
        result_verdict = 'FILTERED'
        result_conf = 0.85
    else:
        result_verdict = 'NO_CANDIDATE'
        result_conf = 0.0

    if label == 'TP':
        correct = result_verdict in ('CONFIRMED', 'UNCERTAIN')
    else:
        correct = result_verdict in ('FILTERED', 'NO_CANDIDATE')

    elapsed = round(time.time() - t0, 4)
    return {
        'sample': sample_dir, 'label': label, 'status': 'OK',
        'candidates': len(fcpv_result.get('candidates', [])),
        'verdict': result_verdict, 'confidence': result_conf,
        'correct': correct, 'elapsed': elapsed,
        'fcpv_vuln': len(fcpv_vuln), 'fcpv_safe': len(fcpv_safe),
        'fcpv_uncertain': len(fcpv_uncertain),
        'pcfc_filtered': pcfc_filtered_count,
    }


def _fallback_to_enhanced(c_file: str) -> Tuple[str, float]:
    """路径约束收集验证判UNCERTAIN时回退到IR级EnhancedFmtDetector."""
    ir_lines = extract_ir(c_file)
    if not ir_lines:
        return ('UNCERTAIN', 0.40)
    detector = EnhancedFmtDetector()
    candidates = detector.detect(ir_lines)
    if not candidates:
        return ('UNCERTAIN', 0.40)
    top = candidates[0]
    if top.verdict == 'CONFIRMED':
        return ('CONFIRMED', top.confidence)
    if top.verdict == 'FILTERED':
        return ('FILTERED', top.confidence)
    return ('UNCERTAIN', 0.40)


def _err_result(sample: str, label: str, error: str) -> Dict[str, Any]:
    return {
        'sample': sample, 'label': label, 'status': 'ERROR',
        'candidates': 0, 'verdict': 'ERROR', 'confidence': 0.0,
        'correct': False, 'error': error, 'elapsed': 0,
    }


def compute_metrics(results: List[Dict]) -> Dict[str, Any]:
    tp = sum(1 for r in results if r.get('correct') and r.get('label') == 'TP')
    tn = sum(1 for r in results if r.get('correct') and r.get('label') == 'FP')
    fp = sum(1 for r in results if not r.get('correct') and r.get('label') == 'FP')
    fn = sum(1 for r in results if not r.get('correct') and r.get('label') == 'TP')
    total_tp = sum(1 for r in results if r.get('label') == 'TP')
    total_fp = sum(1 for r in results if r.get('label') == 'FP')
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / total_tp if total_tp > 0 else 0.0
    f1 = 2*prec*rec/(prec+rec) if (prec+rec) > 0 else 0.0
    fpr = fp / total_fp if total_fp > 0 else 0.0
    return {
        'TP': tp, 'TN': tn, 'FP': fp, 'FN': fn,
        'precision': round(prec, 4), 'recall': round(rec, 4),
        'f1': round(f1, 4), 'fp_rate': round(fpr, 4),
        'total_samples': len(results),
    }


def main():
    verbose = '--verbose' in sys.argv or '-v' in sys.argv
    samples = sorted(FMT_GROUND_TRUTH.keys())

    print(f'[路径约束收集验证 Scanner] Processing {len(samples)} samples...')
    print(f'{"Sample":20s} {"Label":6s} {"Verdict":14s} {"Conf":6s} '
          f'{"路径约束收集验证":10s} {"路径可行性检查":6s} {"OK":4s}')
    print('-' * 72)

    results = []
    for sd in samples:
        r = run_sample_enhanced(sd)
        results.append(r)
        ok = 'OK' if r['correct'] else 'XX'
        fcpv_info = f"V{r.get('fcpv_vuln',0)}/S{r.get('fcpv_safe',0)}/U{r.get('fcpv_uncertain',0)}"
        print(f"{sd:20s} {r['label']:6s} {r['verdict']:14s} "
              f"{r['confidence']:.2f}   {fcpv_info:10s} "
              f"{r.get('pcfc_filtered',0):6d} {ok:4s}")

    metrics = compute_metrics(results)
    print()
    print('=== 路径约束收集验证+路径可行性检查 Format String Detection Metrics ===')
    print(f"  TP={metrics['TP']}  TN={metrics['TN']}  "
          f"FP={metrics['FP']}  FN={metrics['FN']}")
    print(f"  Precision = {metrics['precision']:.1%}")
    print(f"  Recall    = {metrics['recall']:.1%}")
    print(f"  F1        = {metrics['f1']:.4f}")
    print(f"  FP Rate   = {metrics['fp_rate']:.1%}")

    if verbose:
        print()
        for r in results:
            if r.get('status') == 'ERROR':
                print(f"  {r['sample']}: ERROR - {r.get('error', '?')}")

    output_data = {
        'generated': time.strftime('%Y-%m-%d %H:%M:%S'),
        'detector': '路径约束收集验证+路径可行性检查 (source-level constraint propagation)',
        'samples': len(samples),
        'results': results,
        'metrics': metrics,
    }
    out_path = os.path.join(OUTPUT_DIR, 'fcpv_scanner_results.json')
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)
    print(f'\nResults saved: {out_path}')


if __name__ == '__main__':
    main()
