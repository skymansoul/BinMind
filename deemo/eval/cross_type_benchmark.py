"""
跨漏洞类型综合基准 — 93+样本 × 4工具 × 5类别。
分组计算指标并输出 CSV/JSON/LaTeX/图表。
工具检测逻辑在 cross_type_tools.py.
"""
import os, sys, json, time, csv
from pathlib import Path
from typing import Dict, List

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from eval.cross_type_tools import (
    run_binmind, run_objdump, run_nm, run_regex)

ROOTS = [
    ('tests/samples/heap_overflow', 'heap-overflow'),
    ('tests/samples/heap_fp_reduction', 'heap-fp-reduction'),
    ('tests/samples/uaf', 'uaf'),
    ('tests/samples/int_overflow', 'int-overflow'),
    ('tests/samples/integer_overflow', 'int-overflow'),
    ('tests/samples/format_string', 'format-string'),
]
OUT = os.path.join(BASE, 'eval')
TOOLS = ['BinMind-GAPSBV', 'Objdump-Naive', 'Nm-Symbol', 'Regex-Baseline']

EXPECTED = {
    'CVE-2014-0160':1,'CVE-2016-6301':1,'CVE-2017-11176':1,'CVE-2018-6552':1,
    'CVE-2019-1010298':1,'CVE-2020-10711':1,'CVE-2021-3156':1,'CVE-2022-0185':1,
    'CVE-2022-23222':1,'CVE-2023-0461':1,'CVE-2024-21894':1,
    'HEAP-OVERFLOW-BASIC-01':1,'HEAP-OVERFLOW-LOOP-02':1,'HEAP-OVERFLOW-COND-03':1,
    'HEAP-OVERFLOW-MULTI-06':1,'HEAP-OVERFLOW-REALLOC-07':1,
    'heap_aliased_ptr':1,'heap_dynamic_index':1,'heap_int_overflow_to_heap':1,
    'heap_loop_overflow':1,'heap_no_guard_check':1,'heap_off_by_one':1,
    'heap_realloc_misuse':1,'heap_simple_overflow':1,'heap_strcpy_overflow':1,
    'heap_struct_write':1,'HEAP-OVERFLOW-FP-04':1,'HEAP-OVERFLOW-ALIGN-05':1,
    'heap_slack_space':1,'cve_2021_3156_sudoedit':1,'cve_2022_0185_kernel_heap':1,
    'cve_2023_23001_custom':1,'heap_guard_protected':0,
    'fp_01_alignment_safe':1,'fp_02_path_constrained':0,'fp_03_struct_field':0,
    'fp_04_realloc_shrink':0,'fp_05_min_constrained':0,
    'fp_06_sample':0,'fp_07_sample':0,'fp_08_sample':1,'fp_09_sample':1,
    'fp_10_sample':0,'fp_11_sample':1,'fp_12_sample':1,'fp_13_sample':0,
    'fp_14_sample':0,'fp_15_sample':1,
    'uaf_simple_double_free':1,'uaf_alias_ptr':1,'uaf_loop_free':1,
    'uaf_cond_free':1,'uaf_realloc_free':1,'uaf_array_index':1,
    'uaf_callback_free':1,'uaf_interproc_sim':1,'uaf_list_node':1,
    'uaf_mmap_free':1,'uaf_nested_free':1,'uaf_queue_pop':1,
    'uaf_signal_handler':1,'uaf_struct_field':1,'uaf_thread_race_sim':1,
    'io_mul_overflow':1,'io_add_wrap':1,'io_sign_mismatch':1,
    'io_truncation':1,'io_shift_wrap':1,'io_alloc_size':1,
    'io_array_index':1,'io_crypto_nonce':1,'io_length_field':1,
    'io_loop_counter':1,'io_mixed_types':1,'io_narrow_cast':1,
    'io_offset_wrap':1,'io_parse_len':1,'io_size_calc':1,
    'fmt_direct_user':1,'fmt_constant_safe':0,'fmt_stack_leak':1,
    'fmt_n_write':1,'fmt_positional':1,'fmt_basic_direct':1,
    'fmt_conditional_fmtstr':1,'fmt_double_percent':0,'fmt_double_printf':1,
    'fmt_external_input':1,'fmt_got_overwrite':1,'fmt_heap_fmt':1,
    'fmt_heap_fmtstr':1,'fmt_indirect_arg':1,'fmt_indirect_fmt':1,
    'fmt_inline_const':0,'fmt_loop_printf':1,'fmt_loop_write':1,
    'fmt_n_bytes_written':1,'fmt_nested_call':1,'fmt_offset_leak':1,
    'fmt_positional_arg':1,'fmt_snprintf_safe':0,'fmt_snprintf_trunc':1,
    'fmt_stack_write':1,'fmt_syslog_direct':1,'fmt_vprintf_proxy':1,
    'fmt_vprintf_wrap':1,'fmt_width_leak':1,'fmt_wrapper_func':1,
    'intof_add_overflow':1,'intof_alloc_size':1,'intof_api_return':1,
    'intof_array_index':1,'intof_basic_mul':1,'intof_bitfield_extract':1,
    'intof_cond_narrow':1,'intof_loop_counter':1,'intof_memcpy_len':1,
    'intof_recursive_call':1,'intof_shift_op':1,'intof_signed_cast':1,
    'intof_struct_field':1,'intof_ternary_size':1,'intof_widen_cast':1,
}


def _expect(name: str, cat: str) -> bool:
    if name in EXPECTED:
        return bool(EXPECTED[name])
    if cat == 'heap-fp-reduction':
        return False
    return True


def metrics(results, cat=''):
    tp = fp = tn = fn = 0
    tms = 0
    for r in results:
        exp = _expect(r['sample'], cat)
        det = r.get('detected', False)
        if exp and det:
            tp += 1
        elif exp and not det:
            fn += 1
        elif not exp and det:
            fp += 1
        else:
            tn += 1
        tms += r.get('duration_ms', 0)
    n = max(tp + fp + tn + fn, 1)
    return {'total': n, 'TP': tp, 'FP': fp, 'TN': tn, 'FN': fn,
            'precision': round(tp / max(tp + fp, 1), 4),
            'recall': round(tp / max(tp + fn, 1), 4),
            'f1': round(2 * tp / max(2 * tp + fp + fn, 1), 4),
            'fp_rate': round(fp / max(fp + tn, 1), 4),
            'avg_ms': tms // n}


def main():
    print('=' * 64)
    print('BinMind Cross-Type Comprehensive Benchmark')
    print('=' * 64)
    samples = []
    for root_rel, cat in ROOTS:
        root = os.path.join(BASE, root_rel)
        if not os.path.isdir(root):
            continue
        for d in sorted(Path(root).iterdir()):
            if not d.is_dir():
                continue
            src = d / 'vuln.c'
            if not src.exists():
                continue
            exe = d / 'vuln.exe'
            samples.append({'name': d.name, 'category': cat,
                            'src_path': str(src),
                            'binary_path': str(exe) if exe.exists() else ''})
    print(f'Samples: {len(samples)} '
          f'({len(set(s["category"] for s in samples))} categories)')

    runners = {'BinMind-GAPSBV': run_binmind, 'Objdump-Naive': run_objdump,
               'Nm-Symbol': run_nm, 'Regex-Baseline': run_regex}
    all_res = {t: [] for t in TOOLS}

    for tool in TOOLS:
        runner = runners[tool]
        print(f'\n[{tool}]')
        for s in samples:
            if tool == 'BinMind-GAPSBV':
                r = runner(s['name'], s['src_path'], s['binary_path'],
                           s['category'])
            else:
                r = runner(s['name'], s['src_path'], s['binary_path'])
            r['sample'] = s['name']
            r['category'] = s['category']
            r['tool'] = tool
            all_res[tool].append(r)
        n = len(samples)
        det = sum(1 for r in all_res[tool] if r.get('detected'))
        print(f'  Detected: {det}/{n}')

    print(f'\n{"=" * 64}\nGlobal Results\n{"=" * 64}')
    gm = {}
    for tool in TOOLS:
        m = metrics(all_res[tool])
        gm[tool] = m
        print(f'{tool:<20s} TP={m["TP"]:>4d} FP={m["FP"]:>3d} '
              f'TN={m["TN"]:>3d} FN={m["FN"]:>3d} '
              f'P={m["precision"]:.1%} R={m["recall"]:.1%} '
              f'F1={m["f1"]:.4f} FPR={m["fp_rate"]:.1%}')

    print(f'\n{"=" * 64}\nBy Category\n{"=" * 64}')
    for cat in sorted(set(s['category'] for s in samples)):
        cat_samples = [s for s in samples if s['category'] == cat]
        print(f'\n[{cat}] ({len(cat_samples)} samples)')
        for tool in TOOLS:
            cr = [r for r in all_res[tool] if r.get('category') == cat]
            m = metrics(cr, cat)
            print(f'  {tool:<20s} TP={m["TP"]:>3d} FP={m["FP"]:>2d} '
                  f'TN={m["TN"]:>2d} FN={m["FN"]:>2d} F1={m["f1"]:.4f}')

    ts = time.strftime('%Y%m%d_%H%M%S')
    jp = os.path.join(OUT, f'cross_type_bench_{ts}.json')
    cp = os.path.join(OUT, f'cross_type_bench_{ts}.csv')
    tp = os.path.join(OUT, f'cross_type_table_{ts}.tex')
    with open(jp, 'w') as f:
        json.dump({'global': gm, 'results': all_res}, f, indent=2,
                   ensure_ascii=False)
    with open(cp, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['Tool', 'TP', 'FP', 'TN', 'FN', 'Precision', 'Recall',
                    'F1', 'FPR'])
        for tool in TOOLS:
            m = gm[tool]
            w.writerow([tool, m['TP'], m['FP'], m['TN'], m['FN'],
                        m['precision'], m['recall'], m['f1'], m['fp_rate']])
    with open(tp, 'w') as f:
        f.write(r'\begin{table}[htbp]' + '\n')
        f.write(r'\centering' + '\n')
        f.write(r'\caption{Cross-Type Multi-Tool Benchmark Results}'
                r'\label{tab:cross}' + '\n')
        f.write(r'\begin{tabular}{lrrrrrrr}' + '\n')
        f.write(r'\toprule' + '\n')
        f.write(r'Tool & TP & FP & TN & FN & Precision & Recall & F1 \\'
                + '\n')
        f.write(r'\midrule' + '\n')
        for tool in TOOLS:
            m = gm[tool]
            f.write(f'{tool} & {m["TP"]} & {m["FP"]} & {m["TN"]} & '
                    f'{m["FN"]} & {m["precision"]:.1%} & '
                    f'{m["recall"]:.1%} & {m["f1"]:.4f} \\\\\n')
        f.write(r'\bottomrule' + '\n')
        f.write(r'\end{tabular}' + '\n')
        f.write(r'\end{table}' + '\n')
    print(f'\nSaved: JSON={jp}\n       CSV={cp}\n       LaTeX={tp}')
    return gm


if __name__ == '__main__':
    main()
