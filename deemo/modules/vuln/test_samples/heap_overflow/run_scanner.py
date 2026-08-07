"""运行堆溢出检测器扫描所有测试样本.

创建: 2026-05-12  修改: 2026-08-08 (切换到 orchestrator 管线)
用途: 对每个编译好的 sample*/main.exe 执行 analyze_heap 扫描,
      输出每个样本的 detection 结果 (TP/FP/TN/FN).

运行: python run_scanner.py [--verbose] [--samples sample01 sample02 ...]
依赖: 样本已编译.
"""

import os
import sys
import json
import time
from pathlib import Path
from typing import Dict, List


SAMPLE_DIR = Path(__file__).resolve().parent

# 期望结果 (ground truth):
#   TP = true positive (有溢出, 应检出)
#   TN = true negative (无溢出, 不应检出)
GROUPS = [
    ('sample01_direct_overflow', 'TP'),
    ('sample02_int_overflow_to_heap', 'TP'),
    ('sample03_insufficient_guard', 'TP'),
    ('sample04_cross_function_overflow', 'TP'),
    ('sample05_loop_cumulative_overflow', 'TP'),
    ('sample06_sprintf_overflow', 'TP'),
    ('sample07_memcpy_computed_size', 'TP'),
    ('sample08_alignment_padding_safe', 'TN'),
    ('sample09_strncpy_truncation_overflow', 'TP'),
    ('sample10_realloc_shrink_overflow', 'TP'),
    ('sample11_calloc_wraparound', 'TP'),
    ('sample12_conditional_overflow', 'TP'),
    ('sample13_multi_alloc_pointer_confusion', 'TP'),
    ('sample14_nested_struct_overflow', 'TP'),
    ('sample15_properly_guarded_safe', 'TN'),
    ('sample16_exact_boundary_safe', 'TN'),
    ('sample17_large_offset_small_write', 'TN'),
    ('sample18_16bit_overflow_to_heap', 'TP'),
]

GROUND_TRUTH = dict(GROUPS)
N_TP = sum(1 for v in GROUND_TRUTH.values() if v == 'TP')
N_TN = sum(1 for v in GROUND_TRUTH.values() if v == 'TN')


class HeapOverflowDispatcher:
    """堆溢出扫描分发器 — 使用经验证的 analyze_heap() 管线."""

    def __init__(self):
        # 确保 vuln 模块在 path 中
        proj_root = SAMPLE_DIR.parent.parent  # test_samples → vuln
        _heap_src = proj_root / 'src' / 'heap'
        if str(_heap_src) not in sys.path:
            sys.path.insert(0, str(_heap_src))

    def scan(self, elf_path: Path) -> dict:
        """扫描单个二进制文件, 返回检测结果."""
        from orchestrator import analyze_heap

        report = analyze_heap(str(elf_path))

        findings = []
        for f in report.findings:
            findings.append({
                'func': f.get('function', ''),
                'addr': f.get('insn_addr', 0),
                'desc': f.get('reasoning', ''),
                'score': round(1.0 - f.get('fp_probability', 0.5), 3),
                'confidence': round(1.0 - f.get('fp_probability', 0.5), 3),
                'is_fp': f.get('decision') == 'safe',
                'fp_reason': f.get('reasoning', ''),
                'alloc_site': 0,
                'alloc_size': f.get('alloc_size', 0),
                'access_offset': f.get('offset', 0),
                'access_size': f.get('access_size', 0),
                'overflow_bytes': max(0, f.get('access_size', 0) - f.get('alloc_size', 0)),
                'phase': f.get('phase', ''),
                'decision': f.get('decision', ''),
                'safety_verdict': ('DEFINITELY_SAFE' if f.get('decision') == 'safe'
                                  else 'POTENTIALLY_UNSAFE'),
            })

        # real findings: 非 safe 决策
        real_findings = [f for f in findings
                        if f['decision'] not in ('safe', '')
                        and f['confidence'] >= 0.05]
        detected = len(real_findings) > 0

        return {
            'findings': findings,
            'real_findings': real_findings,
            'n_findings': report.raw_findings,
            'n_real': len(real_findings),
            'total_funcs': report.n_user_functions,
            'scanned_funcs': report.n_functions,
            'detected': detected,
            'elapsed_sec': report.elapsed_sec,
            'filtered_fp': report.filtered_fp,
        }


def main():
    import argparse
    ap = argparse.ArgumentParser(description='Run heap overflow scanner on test samples')
    ap.add_argument('--verbose', '-v', action='store_true', help='Show detailed findings')
    ap.add_argument('--samples', nargs='*', help='Specific samples to scan')
    args = ap.parse_args()

    dispatcher = HeapOverflowDispatcher()

    # 发现所有已编译的样本
    all_samples = sorted([
        d for d in SAMPLE_DIR.iterdir()
        if d.is_dir() and d.name.startswith('sample')
        and ((d / 'main').exists() or (d / 'main.exe').exists())
    ], key=lambda d: d.name)

    if args.samples:
        all_samples = [d for d in all_samples if d.name in args.samples]

    if not all_samples:
        print('No compiled samples found. Run compile_samples.py first.')
        return

    results = {}
    tp = tn = fp = fn = 0
    total_time = 0.0

    for d in all_samples:
        elf = d / 'main'
        if not elf.exists():
            elf = d / 'main.exe'
        expected = GROUND_TRUTH.get(d.name, 'TP')
        print(f'  [{d.name}] expected={expected} ', end='', flush=True)

        t0 = time.perf_counter()
        scan_result = dispatcher.scan(elf)
        elapsed = time.perf_counter() - t0
        total_time += elapsed

        detected = scan_result.get('detected', False)
        n_real = scan_result.get('n_real', 0)
        n_total = scan_result.get('n_findings', 0)
        n_filt = scan_result.get('filtered_fp', 0)

        if expected == 'TP':
            if detected:
                verdict = 'TP'; tp += 1
            else:
                verdict = 'FN'; fn += 1
        else:
            if detected:
                verdict = 'FP'; fp += 1
            else:
                verdict = 'TN'; tn += 1

        top_score = max(
            [f['confidence'] for f in scan_result.get('real_findings', [])],
            default=0)
        status = 'OK' if verdict in ('TP', 'TN') else 'MISS'

        print(f'→ {verdict} (real={n_real}, total={n_total}, filt={n_filt}, '
              f'top_conf={top_score:.2f}, {elapsed*1000:.0f}ms) {status}')

        if args.verbose and scan_result.get('real_findings'):
            for f in scan_result['real_findings'][:3]:
                print(f'      [{f["phase"]:15s}] '
                      f'{f["func"]}:0x{f["addr"]:x} '
                      f'conf={f["confidence"]:.2f} '
                      f'overflow={f["overflow_bytes"]}B '
                      f'({f["desc"][:80]})')

        results[d.name] = {
            'expected': expected, 'verdict': verdict,
            'detected': detected, 'n_findings': n_total,
            'n_real_findings': n_real, 'n_filtered_fp': n_filt,
            'top_confidence': top_score,
            'time_ms': round(elapsed * 1000, 1),
            'findings': scan_result.get('real_findings', []) if args.verbose else [],
        }

    # 汇总
    total = tp + tn + fp + fn
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = 2 * precision * recall / max(0.001, precision + recall)

    print(f'\n{"="*60}')
    print(f'SUMMARY: {total} samples ({N_TP} TP + {N_TN} TN expected)')
    print(f'  TP={tp:2d}  TN={tn:2d}  FP={fp:2d}  FN={fn:2d}')
    print(f'  Precision = {tp}/{tp+fp} = {precision:.1%}')
    print(f'  Recall    = {tp}/{tp+fn} = {recall:.1%}')
    print(f'  F1        = {f1:.3f}')
    print(f'  Time      = {total_time*1000:.0f}ms total, '
          f'{total_time/len(all_samples)*1000:.0f}ms avg')

    summary = {
        'tp': tp, 'tn': tn, 'fp': fp, 'fn': fn,
        'precision': round(precision, 4),
        'recall': round(recall, 4),
        'f1': round(f1, 4),
        'total_time_ms': round(total_time * 1000, 0),
        'avg_time_ms': round(total_time / max(1, len(all_samples)) * 1000, 0),
        'per_sample': results,
    }
    res_file = SAMPLE_DIR / 'scan_results.json'
    res_file.write_text(json.dumps(summary, indent=2, ensure_ascii=False))
    print(f'\nSaved: {res_file}')


if __name__ == '__main__':
    main()
