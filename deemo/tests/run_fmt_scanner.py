"""

Format string batch scanner — FCPV+PCFC (source-level) as primary,
EnhancedFmtDetector (IR-level) as UNCERTAIN fallback.

Architecture:
  1. Read C source
  2. FCPV collects 4 constraint types, solves on 3-valued safety lattice
  3. PCFC filters path-unreachable VULN (function-boundary aware)
  4. FCPV VULN (surviving PCFC) → CONFIRMED
  5. FCPV SAFE → FILTERED
  6. FCPV UNCERTAIN → fallback to EnhancedFmtDetector (IR-level)
  7. Compare against ground truth labels
  8. Output per-sample JSON + aggregate metrics

Usage:
  python -m tests.run_fmt_scanner
  python -m tests.run_fmt_scanner --verbose
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Resolve project root
PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES_DIR = os.path.join(PROJECT_DIR, 'samples', 'format_string')
OUTPUT_DIR = os.path.join(PROJECT_DIR, 'eval')
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Import local modules
sys.path.insert(0, PROJECT_DIR)

from core.source_ir_extractor import extract_from_file as extract_ir
from core.format_string_enhanced import EnhancedFmtDetector, FmtCandidate
from core.fcpv_pipeline import fcpv_filter
from core.pcfc_verifier import filter_fmt_by_pcfc
from core.fcpv_constraint_types import SafetyLabel


# ground truth
# TP = 真实格式字符串漏洞, 应被检出
# FP = 安全代码, 应被过滤

FMT_GROUND_TRUTH: Dict[str, str] = {
    'sample_fmt_01': 'TP',   # 基础: fgets→printf(buf)
    'sample_fmt_02': 'FP',   # 安全: printf("%s", buf)
    'sample_fmt_03': 'TP',   # sprintf(dst, buf)
    'sample_fmt_04': 'TP',   # fprintf(stderr, buf)
    'sample_fmt_05': 'TP',   # syslog(buf)
    'sample_fmt_06': 'FP',   # 安全包装: safe_print→printf("%s",s)
    'sample_fmt_07': 'TP',   # argv[1]→printf
    'sample_fmt_08': 'TP',   # fgets→printf (可注入%n)
    'sample_fmt_09': 'FP',   # 常量格式: printf("hello %s", name)
    'sample_fmt_10': 'TP',   # 间接传播: snprintf("%s",buf)→printf(dst)
    'sample_fmt_11': 'TP',   # getenv→printf
    'sample_fmt_12': 'TP',   # recv→printf (网络输入)
    'sample_fmt_13': 'TP',   # 位置参数%n写入: printf(argv[1])
    'sample_fmt_14': 'TP',   # 跨函数fprintf: log_error→fprintf(stderr,user)
    'sample_fmt_15': 'TP',   # syslog+printf: recv_data→syslog(buffer)+printf(buffer)
}


def find_fmt_samples() -> List[str]:
    """扫描 samples/format_string/ 目录, 返回所有样本目录名。"""
    if not os.path.isdir(SAMPLES_DIR):
        return []
    dirs = sorted([
        d for d in os.listdir(SAMPLES_DIR)
        if os.path.isdir(os.path.join(SAMPLES_DIR, d))
        and d.startswith('sample_fmt')
    ])
    return dirs


def get_c_source(sample_dir: str) -> Optional[str]:
    """获取样本的C源文件路径。"""
    full_dir = os.path.join(SAMPLES_DIR, sample_dir)
    c_files = list(Path(full_dir).glob('*.c'))
    if c_files:
        return str(c_files[0])
    return None


def classify_verdict(candidate: FmtCandidate, label: str) -> Tuple[str, bool]:
    """判断检测结果是否正确。"""
    if label == 'TP':
        if candidate.verdict == 'CONFIRMED':
            return ('tp_hit', True)
        elif candidate.verdict == 'UNCERTAIN':
            return ('tp_uncertain', True)
        else:
            return ('fn_missed', False)
    else:  # FP
        if candidate.verdict == 'FILTERED':
            return ('tn_filtered', True)
        elif candidate.verdict == 'CONFIRMED':
            return ('fp_false_alarm', False)
        else:
            return ('fp_uncertain', False)




"""
Format string batch scanner — FCPV+PCFC (source-level) as primary,
EnhancedFmtDetector (IR-level) as UNCERTAIN fallback.

Architecture:
  1. Read C source
  2. FCPV collects 4 constraint types, solves on 3-valued safety lattice
  3. PCFC filters path-unreachable VULN (function-boundary aware)
  4. FCPV VULN (surviving PCFC) → CONFIRMED
  5. FCPV SAFE → FILTERED
  6. FCPV UNCERTAIN → fallback to EnhancedFmtDetector (IR-level)
  7. Compare against ground truth labels
  8. Output per-sample JSON + aggregate metrics

Usage:
  python -m tests.run_fmt_scanner
  python -m tests.run_fmt_scanner --verbose
"""

# Resolve project root
PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES_DIR = os.path.join(PROJECT_DIR, 'samples', 'format_string')
OUTPUT_DIR = os.path.join(PROJECT_DIR, 'eval')

def run_sample(sample_dir: str, verbose: bool = False) -> Dict[str, Any]:
    """对单个格式字符串样本运行FCPV+PCFC检测(EnhancedFmtDetector回退)."""
    label = FMT_GROUND_TRUTH.get(sample_dir, 'TP')
    c_file = get_c_source(sample_dir)

    if not c_file:
        return {
            'sample': sample_dir, 'label': label, 'status': 'MISSING_SOURCE',
            'candidates': 0, 'verdict': 'N/A', 'confidence': 0.0,
            'correct': False, 'error': 'No C source found',
        }

    t0 = time.time()

    try:
        source = Path(c_file).read_text(encoding='utf-8', errors='replace')

        # FCPV源码级约束传播求解
        fcpv_result = fcpv_filter(source)
        fcpv_vuln = fcpv_result.get('vuln', [])
        fcpv_safe = fcpv_result.get('safe', [])
        fcpv_uncertain = fcpv_result.get('uncertain', [])

        # PCFC路径条件过滤VULN
        if fcpv_vuln:
            pcfc_candidates, pcfc_stats = filter_fmt_by_pcfc(
                source, fcpv_vuln)
        else:
            pcfc_candidates, pcfc_stats = [], {'pcfc_filtered': 0}
        remaining_vuln = [
            c for c in pcfc_candidates if c.label == SafetyLabel.VULN
        ]

        elapsed = round(time.time() - t0, 4)

        # 判定优先级 — VULN > UNCERTAIN(回退) > SAFE > NONE
        if remaining_vuln:
            result_verdict = 'CONFIRMED'
            result_conf = max(c.confidence for c in remaining_vuln)
            correct = (label == 'TP')
            detail = f'FCPV+PCFC: {len(remaining_vuln)} VULN ' \
                     f'(pcfc_filtered={pcfc_stats.get("pcfc_filtered", 0)})'
        elif fcpv_uncertain:
            ir_lines = extract_ir(c_file)
            if ir_lines:
                detector = EnhancedFmtDetector()
                candidates = detector.detect(ir_lines)
                if candidates:
                    top = candidates[0]
                    result_verdict = top.verdict
                    result_conf = top.confidence
                    detail = f'EnhancedFmt fallback: {top.summary()}'
                else:
                    result_verdict = 'UNCERTAIN'
                    result_conf = 0.40
                    detail = 'FCPV UNCERTAIN, no IR candidates'
            else:
                result_verdict = 'UNCERTAIN'
                result_conf = 0.40
                detail = 'FCPV UNCERTAIN, IR extraction failed'
            if label == 'TP':
                correct = result_verdict in ('CONFIRMED', 'UNCERTAIN')
            else:
                correct = result_verdict in ('FILTERED', 'NO_CANDIDATE')
        elif fcpv_safe:
            result_verdict = 'FILTERED'
            result_conf = 0.85
            correct = (label == 'FP')
            detail = f'FCPV: {len(fcpv_safe)} SAFE'
        else:
            result_verdict = 'NO_CANDIDATE'
            result_conf = 0.0
            correct = (label == 'FP')
            detail = 'no format string candidates found'

        return {
            'sample': sample_dir,
            'label': label,
            'status': 'OK',
            'candidates': len(fcpv_result.get('candidates', [])),
            'verdict': result_verdict,
            'confidence': result_conf,
            'correct': correct,
            'detail': detail,
            'fcpv_vuln': len(fcpv_vuln),
            'fcpv_safe': len(fcpv_safe),
            'fcpv_uncertain': len(fcpv_uncertain),
            'pcfc_filtered': pcfc_stats.get('pcfc_filtered', 0),
            'elapsed': elapsed,
        }

    except Exception as e:
        return {
            'sample': sample_dir, 'label': label,
            'status': 'ERROR', 'candidates': 0,
            'verdict': 'ERROR', 'confidence': 0.0,
            'correct': False,
            'error': str(e),
            'elapsed': round(time.time() - t0, 4),
        }


def compute_metrics(results: List[Dict]) -> Dict[str, Any]:
    """计算总体评估指标。"""
    tp = sum(1 for r in results if r.get('correct') and r.get('label') == 'TP')
    tn = sum(1 for r in results if r.get('correct') and r.get('label') == 'FP')
    fp = sum(1 for r in results if not r.get('correct') and r.get('label') == 'FP')
    fn = sum(1 for r in results if not r.get('correct') and r.get('label') == 'TP')

    total_tp = sum(1 for r in results if r.get('label') == 'TP')
    total_fp = sum(1 for r in results if r.get('label') == 'FP')

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / total_tp if total_tp > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / len(results) if results else 0.0
    fp_rate = fp / total_fp if total_fp > 0 else 0.0

    return {
        'TP': tp, 'TN': tn, 'FP': fp, 'FN': fn,
        'precision': round(precision, 4),
        'recall': round(recall, 4),
        'f1': round(f1, 4),
        'accuracy': round(accuracy, 4),
        'fp_rate': round(fp_rate, 4),
        'total_samples': len(results),
        'ok_samples': sum(1 for r in results if r.get('status') == 'OK'),
    }


# main

def main():
    verbose = '--verbose' in sys.argv or '-v' in sys.argv

    samples = find_fmt_samples()
    if not samples:
        print('[ERROR] No format string samples found')
        return

    print(f'[FCPV+PCFC Scanner] Processing {len(samples)} samples...')
    print(f'{"Sample":20s} {"Label":6s} {"Verdict":14s} {"Conf":6s} '
          f'{"FCPV":10s} {"PCFC":6s} {"OK":4s}')
    print('-' * 72)

    results = []
    for sd in samples:
        result = run_sample(sd, verbose)
        results.append(result)
        ok_mark = 'OK' if result['correct'] else 'XX'
        fcpv_info = f"V{result.get('fcpv_vuln',0)}/S{result.get('fcpv_safe',0)}/U{result.get('fcpv_uncertain',0)}"
        print(f"{sd:20s} {result['label']:6s} {result['verdict']:14s} "
              f"{result['confidence']:.2f}   {fcpv_info:10s} "
              f"{result.get('pcfc_filtered',0):6d} {ok_mark:4s}")

# metrics
    metrics = compute_metrics(results)
    print()
    print('=== FCPV+PCFC Format String Detection Metrics ===')
    print(f"  TP={metrics['TP']}  TN={metrics['TN']}  "
          f"FP={metrics['FP']}  FN={metrics['FN']}")
    print(f"  Precision = {metrics['precision']:.1%}")
    print(f"  Recall    = {metrics['recall']:.1%}")
    print(f"  F1        = {metrics['f1']:.4f}")
    print(f"  Accuracy  = {metrics['accuracy']:.1%}")
    print(f"  FP Rate   = {metrics['fp_rate']:.1%}")

# per-sample detail
    if verbose:
        print()
        for r in results:
            if r.get('detail'):
                print(f"  {r['sample']}: {r['detail']}")
            if r.get('ir_count'):
                print(f"    IR lines: {r['ir_count']}")

# save results
    output_data = {
        'generated': time.strftime('%Y-%m-%d %H:%M:%S'),
        'detector': 'FCPV+PCFC (source-level constraint propagation)',
        'samples': len(samples),
        'results': results,
        'metrics': metrics,
        'fcpv_summary': {
            'total_vuln': sum(r.get('fcpv_vuln', 0) for r in results),
            'total_safe': sum(r.get('fcpv_safe', 0) for r in results),
            'total_uncertain': sum(r.get('fcpv_uncertain', 0) for r in results),
            'total_pcfc_filtered': sum(r.get('pcfc_filtered', 0) for r in results),
        },
    }

    out_path = os.path.join(OUTPUT_DIR, 'fmt_benchmark_results.json')
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)
    print(f'\nResults saved: {out_path}')


if __name__ == '__main__':
    main()
