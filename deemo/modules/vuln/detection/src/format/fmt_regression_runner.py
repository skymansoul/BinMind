"""格式化字符串漏洞回归测试运行器 — 编译→扫描→收集结果.

创建: 2025-04-17
用途: 对 fmt_samples/ 中的每个样本执行检测, 验证 taint_format_checker +
      fmt_arg_verifier 的效果。检测逻辑在 fmt_detector.py 中。

使用: python fmt_regression_runner.py [--quick] [--verbose] [--json PATH]
"""

import json
import time
import subprocess
from pathlib import Path
from typing import Dict

try:
    from .fmt_detector import (disassemble_elf, extract_rodata_strings,
                               detect_fmt_vuln, detect_fmt_vuln_enhanced)
except ImportError:
    from fmt_detector import (disassemble_elf, extract_rodata_strings,
                              detect_fmt_vuln, detect_fmt_vuln_enhanced)

_HERE = Path(__file__).resolve().parent
_SAMPLES = _HERE / 'fmt_samples'

GROUND_TRUTH: Dict[str, str] = {
    'sample01_direct_fmt_vuln': 'TP',
    'sample02_fmt_str_write_pct_n': 'TP',
    'sample03_indirect_fmt_leak': 'TP',
    'sample04_sprintf_fmt_vuln': 'TP',
    'sample05_fprintf_fmt_vuln': 'TP',
    'sample06_syslog_fmt_vuln': 'TP',
    'sample07_info_leak_stack_read': 'TP',
    'sample08_wrapper_fmt_vuln': 'TP',
    'sample09_fmt_str_const_safe': 'TN',
    'sample10_debug_log_safe': 'TN',
    'sample11_fmt_str_in_rodata_safe': 'TN',
    'sample12_snprintf_bounded_safe': 'TN',
    'sample13_dynamic_fmt_controlled': 'TP',
    'sample14_wide_char_fmt': 'TP',
    'sample15_pct_n_write_primitive': 'TP',
    'sample16_buffered_fmt_leak': 'TP',
}


def compile_sample(sample_dir: Path) -> bool:
    """编译单个样本 — 优先使用 Makefile, 否则直接 gcc."""
    main_c = sample_dir / 'main.c'
    if not main_c.exists():
        return False
    makefile = sample_dir / 'Makefile'
    if makefile.exists():
        r = subprocess.run(['make', '-C', str(sample_dir)],
                          capture_output=True, text=True, timeout=15)
        if r.returncode == 0:
            return True
    r = subprocess.run(
        ['gcc', '-Wall', '-g', '-O0', '-o',
         str(sample_dir / 'main'), str(main_c)],
        capture_output=True, text=True, timeout=15)
    return r.returncode == 0


def main():
    import argparse
    ap = argparse.ArgumentParser(description='Format String Regression Runner')
    ap.add_argument('--quick', action='store_true', help='Skip compilation')
    ap.add_argument('--verbose', '-v', action='store_true')
    ap.add_argument('--json', type=str, default=None, help='Output JSON path')
    args = ap.parse_args()

    samples = sorted([d for d in _SAMPLES.iterdir()
                     if d.is_dir() and d.name.startswith('sample')],
                    key=lambda d: d.name)

    if not samples:
        print('No fmt samples found.')
        return

    results = {}
    tp = tn = fp = fn = 0
    total_time = 0.0

    for d in samples:
        expected = GROUND_TRUTH.get(d.name, 'TP')
        elf = d / 'main'
        if not elf.exists():
            elf_exe = d / 'main.exe'
            if elf_exe.exists():
                elf = elf_exe

        if not args.quick and not elf.exists():
            compile_sample(d)

        if not elf.exists():
            print(f'  [{d.name}] NO BINARY')
            continue

        t0 = time.perf_counter()
        funcs = disassemble_elf(elf)
        all_findings = []
        main_detected = False
        lib_findings = 0
        lib_vuln_funcs = set()  # 非main函数中检出漏洞的函数名
        rodata_strs = extract_rodata_strings(elf)

        for func_name, insns, addrs in funcs:
            scan = detect_fmt_vuln_enhanced(insns, addrs, rodata_strs)
            if func_name == 'main':
                main_detected = scan['detected']
            elif scan['detected']:
                lib_findings += scan['n_findings']
                lib_vuln_funcs.add(func_name)
            all_findings.extend(scan['findings'])

        # 跨函数传播: main 调用了有漏洞的 wrapper 函数 → 判定检出
        # 设计决策: wrapper 函数 (如 log_message) 内部 vprintf(fmt, args),
        # main 传 argv 作为参数, 漏洞在 wrapper 内但 taint 来自 main.
        cross_func_detected = False
        if not main_detected and lib_vuln_funcs:
            # 排除运行时库函数 (以下划线开头), 仅传播用户定义的 wrapper
            user_vuln_funcs = {f for f in lib_vuln_funcs
                               if not f.startswith('_')}
            if user_vuln_funcs:
                for func_name, insns, addrs in funcs:
                    if func_name != 'main':
                        continue
                    for instr in insns:
                        instr_lower = instr.lower()
                        if not instr_lower.startswith('call'):
                            continue
                        for vf in user_vuln_funcs:
                            if vf in instr_lower:
                                cross_func_detected = True
                                break
                        if cross_func_detected:
                            break

        detected = main_detected or cross_func_detected

        elapsed = time.perf_counter() - t0
        total_time += elapsed

        if expected == 'TP':
            verdict = 'TP' if detected else 'FN'
            tp += 1 if detected else 0
            fn += 0 if detected else 1
        else:
            verdict = 'FP' if detected else 'TN'
            fp += 1 if detected else 0
            tn += 0 if detected else 1

        status = 'OK' if verdict in ('TP', 'TN') else 'MISS'
        top_conf = max((f.get('confidence', 0) for f in all_findings), default=0)
        classes = set(f.get('vuln_class', '?') for f in all_findings)
        main_found = sum(1 for f in all_findings if f.get('addr', 0) >= 0)
        print(f'  [{d.name}] expected={expected} -> {verdict} '
              f'(main_detected={main_detected}, lib_noise={lib_findings}, '
              f'{elapsed*1000:.0f}ms) {status}')

        results[d.name] = {
            'expected': expected, 'verdict': verdict,
            'detected': detected, 'n_findings': len(all_findings),
            'top_confidence': top_conf, 'time_ms': round(elapsed * 1000, 1),
        }

    total = tp + tn + fp + fn
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = 2 * precision * recall / max(0.001, precision + recall)

    print(f'\n{"="*60}')
    print(f'FORMAT STRING REGRESSION: {total} samples')
    print(f'  TP={tp}  TN={tn}  FP={fp}  FN={fn}')
    print(f'  Precision={precision:.1%}  Recall={recall:.1%}  F1={f1:.3f}')

    summary = {
        'tp': tp, 'tn': tn, 'fp': fp, 'fn': fn,
        'precision': round(precision, 4),
        'recall': round(recall, 4),
        'f1': round(f1, 4),
        'avg_time_ms': round(total_time / max(1, total) * 1000, 0),
        'per_sample': results,
    }

    out_file = _HERE / 'fmt_scan_results.json'
    out_file.write_text(json.dumps(summary, indent=2, ensure_ascii=False))
    print(f'Saved: {out_file}')

    if args.json:
        json_path = Path(args.json)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main()
