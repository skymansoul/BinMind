"""
UAF batch scanner — compile→extract→detect→collect for 15 UAF samples.

Architecture mirrors tests/run_scanner.py (heap overflow batch runner):
  1. Read C source via source_ir_extractor
  2. Run EnhancedUafDetector (TARPS pipeline)
  3. Compare against ground truth labels
  4. Output per-sample JSON + aggregate metrics

Usage:
  python -m tests.run_uaf_scanner
  python -m tests.run_uaf_scanner --verbose
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Resolve project root
PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES_DIR = os.path.join(PROJECT_DIR, 'samples', 'uaf')
OUTPUT_DIR = os.path.join(PROJECT_DIR, 'eval')
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Import local modules
sys.path.insert(0, PROJECT_DIR)

from core.source_ir_extractor import extract_from_file as extract_ir
from core.uaf_enhanced import EnhancedUafDetector, UafCandidate


# ground truth
# 标签: TP=真漏洞, FP=安全代码(误报应被过滤)
# TARPS期望: TP样本 → CONFIRMED; FP样本 → FILTERED

UAF_GROUND_TRUTH: Dict[str, str] = {
    'sample_uaf_01': 'TP',   # 基础UAF: malloc→free→use
    'sample_uaf_02': 'FP',   # NULL置零: free→p=NULL→if(p)
    'sample_uaf_03': 'TP',   # 别名UAF: q=p→free(p)→use(q)
    'sample_uaf_04': 'FP',   # 立即复用: free→p=malloc→use
    'sample_uaf_05': 'TP',   # Double free
    'sample_uaf_06': 'TP',   # 条件分支free后UAF
    'sample_uaf_07': 'TP',   # 循环内free后遍历
    'sample_uaf_08': 'TP',   # 跨函数UAF: free在callee, use在caller
    'sample_uaf_09': 'TP',   # 全局指针UAF
    'sample_uaf_10': 'TP',   # 结构体成员指针UAF
    'sample_uaf_11': 'TP',   # 多层别名链: p→q→r→free→use(r)
    'sample_uaf_12': 'TP',   # realloc后旧指针UAF
    'sample_uaf_13': 'FP',   # 安全: 双重指针NULL置零
    'sample_uaf_14': 'TP',   # switch-case复杂控制流UAF
    'sample_uaf_15': 'TP',   # 别名未NULL置零的真UAF
}


def find_uaf_samples() -> List[str]:
    """扫描 samples/uaf/ 目录, 返回所有样本目录名。"""
    if not os.path.isdir(SAMPLES_DIR):
        return []
    dirs = sorted([
        d for d in os.listdir(SAMPLES_DIR)
        if os.path.isdir(os.path.join(SAMPLES_DIR, d))
        and d.startswith('sample_uaf')
    ])
    return dirs


def get_c_source(sample_dir: str) -> Optional[str]:
    """获取样本的C源文件路径。"""
    full_dir = os.path.join(SAMPLES_DIR, sample_dir)
    c_files = list(Path(full_dir).glob('*.c'))
    if c_files:
        return str(c_files[0])
    return None


def classify_verdict(candidate: UafCandidate, label: str) -> Tuple[str, bool]:
    """判断检测结果是否正确。

    TP样本: CONFIRMED或UNCERTAIN → correct (检出)
    FP样本: FILTERED → correct (正确过滤), CONFIRMED → wrong (误报)
    """
    if label == 'TP':
        # 检出或不确定都算部分命中
        if candidate.verdict == 'CONFIRMED':
            return ('tp_hit', True)
        elif candidate.verdict == 'UNCERTAIN':
            return ('tp_uncertain', True)
        else:
            return ('fn_missed', False)
    else:  # FP样本应当是安全的
        if candidate.verdict == 'FILTERED':
            return ('tn_filtered', True)
        elif candidate.verdict == 'CONFIRMED':
            return ('fp_false_alarm', False)
        else:
            return ('fp_uncertain', False)


def run_sample(sample_dir: str, verbose: bool = False) -> Dict[str, Any]:
    """对单个UAF样本运行TARPS检测。"""
    label = UAF_GROUND_TRUTH.get(sample_dir, 'TP')
    c_file = get_c_source(sample_dir)

    if not c_file:
        return {
            'sample': sample_dir, 'label': label, 'status': 'MISSING_SOURCE',
            'candidates': 0, 'verdict': 'N/A', 'confidence': 0.0,
            'correct': False, 'error': 'No C source found',
        }

    t0 = time.time()

    try:
        # 提取IR
        ir_lines = extract_ir(c_file)
        if not ir_lines:
            return {
                'sample': sample_dir, 'label': label,
                'status': 'NO_IR', 'candidates': 0,
                'verdict': 'N/A', 'confidence': 0.0,
                'correct': False,
                'error': 'source_ir_extractor returned empty',
                'elapsed': round(time.time() - t0, 4),
            }

        # TARPS检测
        detector = EnhancedUafDetector()
        candidates = detector.detect(ir_lines)

        elapsed = round(time.time() - t0, 4)

        if not candidates:
            result_verdict = 'NO_CANDIDATE'
            result_conf = 0.0
            correct = (label == 'FP')  # FP样本无检出=正确过滤
            detail = 'no UAF candidates found'
        else:
            # 取最高置信度候选
            top = candidates[0]
            result_verdict = top.verdict
            result_conf = top.confidence
            detail = top.summary()
            result_type, correct = classify_verdict(top, label)

        return {
            'sample': sample_dir,
            'label': label,
            'status': 'OK',
            'candidates': len(candidates),
            'verdict': result_verdict,
            'confidence': result_conf,
            'correct': correct,
            'detail': detail,
            'stats': detector.stats,
            'elapsed': elapsed,
            'ir_count': len(ir_lines),
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

    total_tp_samples = sum(1 for r in results if r.get('label') == 'TP')
    total_fp_samples = sum(1 for r in results if r.get('label') == 'FP')

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / total_tp_samples if total_tp_samples > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / len(results) if results else 0.0
    fp_rate = fp / total_fp_samples if total_fp_samples > 0 else 0.0

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

    samples = find_uaf_samples()
    if not samples:
        print('[ERROR] No UAF samples found')
        return

    print(f'[TARPS UAF Scanner] Processing {len(samples)} samples...')
    print(f'{"Sample":20s} {"Label":6s} {"Verdict":14s} {"Conf":6s} {"OK":6s}')
    print('-' * 56)

    results = []
    for sd in samples:
        result = run_sample(sd, verbose)
        results.append(result)
        ok_mark = 'OK' if result['correct'] else 'XX'
        print(f"{sd:20s} {result['label']:6s} {result['verdict']:14s} "
              f"{result['confidence']:.2f}   {ok_mark}")

# metrics
    metrics = compute_metrics(results)
    print()
    print('=== UAF TARPS Detection Metrics ===')
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

# save results
    output_data = {
        'generated': time.strftime('%Y-%m-%d %H:%M:%S'),
        'detector': 'TARPS-v1 (EnhancedUafDetector)',
        'samples': len(samples),
        'results': results,
        'metrics': metrics,
        'stage_breakdown': {
            'stageA_null_guard': sum(
                r.get('stats', {}).get('stageA_null_guards', 0) for r in results),
            'stageB_reassign': sum(
                r.get('stats', {}).get('stageB_reassign', 0) for r in results),
            'stageC_aliases': sum(
                r.get('stats', {}).get('stageC_aliases', 0) for r in results),
            'stageD_paths': sum(
                r.get('stats', {}).get('stageD_paths', 0) for r in results),
            'stageE_confirmed': sum(
                r.get('stats', {}).get('confirmed', 0) for r in results),
        },
    }

    out_path = os.path.join(OUTPUT_DIR, 'uaf_benchmark_results.json')
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)
    print(f'\nResults saved: {out_path}')


if __name__ == '__main__':
    main()
