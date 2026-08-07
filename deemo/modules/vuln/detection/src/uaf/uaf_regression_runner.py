"""UAF 回归测试运行器 — 编译→反汇编→UAF检测→收集结果.

创建: 2026-04-17 | 更新: 2026-08-08 (集成 UAFTemporalVerifier)
用途: 对 uaf_samples/ 中的每个样本做:
  1. 编译 (gcc)
  2. 反汇编 (objdump)
  3. UAF 检测 (uaf_detector → UAFTemporalVerifier 四态时序分析)
  4. 结果汇总 + 指标计算

使用: python uaf_regression_runner.py [--quick] [--verbose]
"""

import os
import sys
import json
import time
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    from .uaf_detector import detect_uaf
except ImportError:
    from uaf_detector import detect_uaf

_HERE = Path(__file__).resolve().parent
_SAMPLES = _HERE / 'uaf_samples'
OBJDUMP = os.environ.get('OBJDUMP', 'objdump')

# Ground truth
GROUND_TRUTH = {
    'sample01_basic_uaf': 'TP',
    'sample02_double_free': 'TP',
    'sample03_realloc_uaf': 'TP',
    'sample04_cross_function_uaf': 'TP',
    'sample05_alias_uaf': 'TP',
    'sample06_struct_field_uaf': 'TP',
    'sample07_conditional_uaf': 'TP',
    'sample08_loop_uaf': 'TP',
    'sample09_list_node_uaf': 'TP',
    'sample10_callback_uaf': 'TP',
    'sample11_realloc_zero_uaf': 'TP',
    'sample12_vector_uaf': 'TP',
    'sample13_multi_free_uaf': 'TP',
    'sample14_thread_uaf': 'TP',
    'sample15_null_after_free_safe': 'TN',
    'sample16_guard_before_use_safe': 'TN',
    'sample17_copy_then_free_safe': 'TN',
    'sample18_realloc_same_ptr_safe': 'TN',
}


def disassemble(elf_path: Path) -> List[Tuple[str, List[str], List[int]]]:
    """反汇编 ELF → [(func_name, [insns], [addrs])]."""
    r = subprocess.run(
        [OBJDUMP, '-d', '-M', 'intel', str(elf_path)],
        capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        return []

    current_func = ''
    current_insns: List[str] = []
    current_addrs: List[int] = []
    functions = []

    for line in r.stdout.split('\n'):
        line = line.rstrip()
        if not line:
            continue
        if line.endswith('>:') and not line.startswith(' '):
            if current_insns:
                functions.append((current_func, current_insns, current_addrs))
            current_func = line.strip('<:>').split('<')[-1].rstrip('>:')
            current_insns = []
            current_addrs = []
            continue
        if ':\t' in line and not line.startswith('Disassembly'):
            parts = line.split(':\t', 1)
            try:
                addr = int(parts[0].strip(), 16)
                instr = parts[1].split('\t')[-1].strip()
            except ValueError:
                continue
            current_insns.append(instr)
            current_addrs.append(addr)

    if current_insns:
        functions.append((current_func, current_insns, current_addrs))
    return functions



def compile_sample(sample_dir: Path) -> bool:
    """编译单个样本."""
    makefile = sample_dir / 'Makefile'
    main_c = sample_dir / 'main.c'
    if not main_c.exists():
        return False
    if makefile.exists():
        r = subprocess.run(['make', '-C', str(sample_dir)],
                          capture_output=True, text=True, timeout=15)
        if r.returncode == 0:
            return True
    # fallback: 直接 gcc
    r = subprocess.run(
        ['gcc', '-Wall', '-g', '-O0', '-o',
         str(sample_dir / 'main'), str(main_c)],
        capture_output=True, text=True, timeout=15)
    return r.returncode == 0


def main():
    import argparse
    ap = argparse.ArgumentParser(description='UAF Regression Runner')
    ap.add_argument('--quick', action='store_true', help='Skip compilation')
    ap.add_argument('--verbose', '-v', action='store_true')
    ap.add_argument('--json', type=str, default=None,
                   help='Output JSON path')
    args = ap.parse_args()

    samples = sorted([d for d in _SAMPLES.iterdir()
                     if d.is_dir() and d.name.startswith('sample')],
                    key=lambda d: d.name)

    if not samples:
        print('No UAF samples found.')
        return

    n_total = len(samples)
    results = {}
    tp = tn = fp = fn = 0
    total_time = 0.0

    for d in samples:
        expected = GROUND_TRUTH.get(d.name, 'TP')
        elf = d / 'main'
        # Windows: 二进制为 main.exe
        if not elf.exists():
            elf_exe = d / 'main.exe'
            if elf_exe.exists():
                elf = elf_exe

        # Compile
        if not args.quick and not elf.exists():
            ok = compile_sample(d)
            if not ok:
                print(f'  [{d.name}] COMPILE FAILED')
                continue

        if not elf.exists():
            print(f'  [{d.name}] NO BINARY — run without --quick first')
            continue

        t0 = time.perf_counter()
        funcs = disassemble(elf)
        all_findings = []
        main_detected = False
        lib_findings = 0
        verifier_stats = {}

        for func_name, insns, addrs in funcs:
            scan = detect_uaf(insns, addrs)
            is_main = (func_name == 'main')
            if is_main:
                main_detected = scan['detected']
            elif scan['detected']:
                # CRT/库函数中的发现 — 不计入判定, 但记录
                lib_findings += scan.get('n_real_findings',
                                        scan['n_findings'])
            all_findings.extend(scan['findings'])
            if scan.get('verifier_stats'):
                verifier_stats = scan['verifier_stats']

        # 仅用 main() 的发现做判定 — 回归样本是自包含的
        detected = main_detected

        elapsed = time.perf_counter() - t0
        total_time += elapsed

        # 判定 — 使用时序验证器成果
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

        status = 'OK' if verdict in ('TP', 'TN') else 'MISS'
        top_conf = max((f.get('confidence', 0) for f in all_findings), default=0)
        verdicts_in = set(f.get('verdict', '?') for f in all_findings)
        main_uaf = sum(1 for f in all_findings
                      if f.get('verdict') == 'DEFINITELY_UAF')
        print(f'  [{d.name}] expected={expected} -> {verdict} '
              f'(main_uaf={main_uaf}, lib_noise={lib_findings}, '
              f'{elapsed*1000:.0f}ms) {status}')

        results[d.name] = {
            'expected': expected, 'verdict': verdict,
            'detected': detected, 'n_findings': len(all_findings),
            'main_uaf_count': sum(1 for f in all_findings
                               if f.get('verdict') == 'DEFINITELY_UAF'),
            'lib_findings': lib_findings,
            'top_confidence': top_conf, 'time_ms': round(elapsed * 1000, 1),
            'temporal_verdicts': sorted(verdicts_in),
            'verifier_stats': verifier_stats,
        }

    total = tp + tn + fp + fn
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = 2 * precision * recall / max(0.001, precision + recall)

    print(f'\n{"="*60}')
    print(f'UAF REGRESSION: {total} samples')
    print(f'  TP={tp}  TN={tn}  FP={fp}  FN={fn}')
    print(f'  Precision={precision:.1%}  Recall={recall:.1%}  F1={f1:.3f}')
    print(f'  Avg time: {total_time/max(1,total)*1000:.0f}ms/sample')

    summary = {
        'tp': tp, 'tn': tn, 'fp': fp, 'fn': fn,
        'precision': round(precision, 4),
        'recall': round(recall, 4),
        'f1': round(f1, 4),
        'avg_time_ms': round(total_time / max(1, total) * 1000, 0),
        'per_sample': results,
    }

    out_file = _HERE / 'uaf_scan_results.json'
    out_file.write_text(json.dumps(summary, indent=2, ensure_ascii=False))
    print(f'Saved: {out_file}')

    if args.json:
        json_path = Path(args.json)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False))
        print(f'Copied to: {json_path}')


if __name__ == '__main__':
    main()
