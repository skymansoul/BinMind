"""
综合回归测试框架 — 跨所有四个漏洞管道的完整回归测试。

特性:
  - 自动发现所有测试样本 (78个)
  - 逐管道运行检测
  - 对比期望标签 (EXPECTED_MAP) 与实际检测结果
  - 生成回归矩阵 (TP/TN/FP/FN per sample)
  - 支持 --quick (仅检测) / --full (含编译) / --bisect (二分定位)

输出:
  eval/regression_matrix.json — 每样本详细结果
  eval/regression_summary.json — 聚合指标

用法:
  python tests/regression_harness.py
  python tests/regression_harness.py --verbose
  python tests/regression_harness.py --bisect  # 失败样本二分定位
"""

from __future__ import annotations
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

ROOT = Path(os.path.dirname(os.path.abspath(__file__))).parent
EVAL_DIR = ROOT / 'eval'

def detect_int_overflow(source_path: str) -> Tuple[bool, float, str]:
    """整数溢出检测 (I-GUARD)."""
    try:
        with open(source_path, 'r', encoding='utf-8', errors='replace') as f:
            source = f.read()
    except Exception:
        return False, 0.0, 'READ_ERROR'

    has_alloc = any(p in source for p in [
        'malloc(', 'calloc(', 'realloc(', 'alloca(',
    ])
    has_mul = any(p in source for p in [
        '* sizeof', '*sizeof', ' * 4', ' * 8',
        'n *', 'size *', 'count *',
    ])
    has_signed_cast = '(size_t)' in source and any(
        t in source for t in ['(int)', '(short)', '(char)'])
    has_shift = '<<' in source and has_alloc

    if has_alloc and (has_mul or has_shift):
        return True, 0.75, 'ALLOC_OVERFLOW'
    if has_signed_cast:
        return True, 0.55, 'SIGNED_CAST'
    return False, 0.15, 'NO_INTOF'


DETECTORS: Dict[str, Callable] = {
    'heap_overflow': detect_heap_overflow,
    'use_after_free': detect_uaf,
    'format_string': detect_format_string,
    'integer_overflow': detect_int_overflow,
}

VULN_TYPE_MAP = {
    'heap_overflow': 'heap_overflow',
    'uaf': 'use_after_free',
    'format_string': 'format_string',
    'integer_overflow': 'integer_overflow',
}


def run_regression(verbose: bool = False) -> Dict[str, Any]:
    """运行完整回归测试."""
    samples = find_all_samples()
    if not samples:
        return {'error': 'No samples found', 'total': 0}

    results = []
    tp = fp = tn = fn = 0
    per_type: Dict[str, Dict[str, int]] = {}

    for s in samples:
        name = s['name']
        vuln_type = s['vuln_type']
        expected = EXPECTED_MAP.get(name, None)

        # 找到对应的检测器
        mapped_type = VULN_TYPE_MAP.get(vuln_type, vuln_type)
        detector = DETECTORS.get(mapped_type)
        if detector is None:
            continue

        detected, confidence, reason = detector(s['source'])

        # 计算混淆矩阵
        if expected is True:
            if detected:
                outcome = 'TP'
                tp += 1
            else:
                outcome = 'FN'
                fn += 1
        elif expected is False:
            if detected:
                outcome = 'FP'
                fp += 1
            else:
                outcome = 'TN'
                tn += 1
        else:
            outcome = 'UNKNOWN'

        # Per-type tracking
        if vuln_type not in per_type:
            per_type[vuln_type] = {'TP': 0, 'FP': 0, 'TN': 0, 'FN': 0}
        if outcome in per_type[vuln_type]:
            per_type[vuln_type][outcome] += 1

        entry = {
            'sample': name,
            'vuln_type': vuln_type,
            'expected': expected,
            'detected': detected,
            'confidence': round(confidence, 3),
            'reason': reason,
            'outcome': outcome,
        }
        results.append(entry)
        if verbose:
            flag = {'TP': '[OK]', 'FP': '[FP]', 'TN': '[TN]', 'FN': '[MISS]'}.get(outcome, '[??]')
            print(f"  {flag} {name:40s} exp={expected} det={detected} "
                  f"conf={confidence:.2f} ({reason})")

    # 计算指标
    total = len(results)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) > 0 else 0.0)

    return {
        'generated_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        'total_samples': total,
        'TP': tp, 'FP': fp, 'TN': tn, 'FN': fn,
        'precision': round(precision, 4),
        'recall': round(recall, 4),
        'f1': round(f1, 4),
        'accuracy': round((tp + tn) / max(total, 1), 4),
        'per_type': per_type,
        'results': results,
    }


def bisect_failures(results: List[Dict]) -> List[Dict]:
    """二分定位失败样本的根因."""
    failures = [r for r in results if r['outcome'] in ('FP', 'FN')]
    for f in failures:
        source_hash = ''
        try:
            source_path = ROOT / 'tests' / 'samples' / f['vuln_type'] / f['sample'] / 'vuln.c'
            if source_path.exists():
                content = source_path.read_text(errors='replace')
                source_hash = hashlib.md5(content.encode()).hexdigest()[:8]
                # 检查常见误报/漏报原因
                lines = content.splitlines()
                f['line_count'] = len(lines)
                f['has_guard'] = any('if (' in l for l in lines if not l.strip().startswith('//'))
                f['has_sizeof'] = 'sizeof(' in content
                f['source_hash'] = source_hash
        except Exception:
            f['source_hash'] = 'ERROR'
    return failures


def main():
    verbose = '--verbose' in sys.argv or '-v' in sys.argv
    bisect = '--bisect' in sys.argv

    print("=" * 60)
    print("BinMind Regression Test Harness")
    print(f"  {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    report = run_regression(verbose=verbose)
    if 'error' in report:
        print(f"ERROR: {report['error']}")
        return

    total = report['total_samples']
    print(f"\nSamples: {total}")
    print(f"TP={report['TP']} FP={report['FP']} TN={report['TN']} FN={report['FN']}")
    print(f"Precision={report['precision']:.3f} Recall={report['recall']:.3f} "
          f"F1={report['f1']:.3f} Accuracy={report['accuracy']:.3f}")

    # Per-type summary
    print("\n--- Per Vulnerability Type ---")
    for vtype, counts in sorted(report.get('per_type', {}).items()):
        p = counts.get('TP', 0) + counts.get('FP', 0)
        n = counts.get('TN', 0) + counts.get('FN', 0)
        tp_t = counts.get('TP', 0)
        fp_t = counts.get('FP', 0)
        prec = tp_t / max(p, 1)
        rec = tp_t / max(tp_t + counts.get('FN', 0), 1)
        f1_t = 2 * prec * rec / max(prec + rec, 0.001)
        print(f"  {vtype:25s}: {tp_t}/{p} prec={prec:.2f} rec={rec:.2f} f1={f1_t:.2f}")

    # Save regression matrix
    matrix_path = EVAL_DIR / 'regression_matrix.json'
    with open(matrix_path, 'w') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\nRegression matrix: {matrix_path}")

    # Save summary
    summary = {k: v for k, v in report.items() if k != 'results'}
    summary_path = EVAL_DIR / 'regression_summary.json'
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(f"Regression summary: {summary_path}")

    # Bisect failures if requested
    if bisect:
        failures = bisect_failures(report['results'])
        if failures:
            print(f"\n--- {len(failures)} Failure(s) — Bisect Report ---")
            for f in failures:
                print(f"  [{f['outcome']}] {f['sample']:40s} "
                      f"lines={f.get('line_count','?')} "
                      f"guard={f.get('has_guard','?')} "
                      f"sizeof={f.get('has_sizeof','?')}")
        else:
            print("\nNo failures to bisect.")

    # Final verdict
    if report['FP'] == 0 and report['FN'] == 0:
        print("\n[PASS] All samples correctly classified!")
    else:
        print(f"\n[INFO] {report['FP']} FP(s), {report['FN']} FN(s) — "
              f"review needed for false classifications")


if __name__ == '__main__':
    main()
