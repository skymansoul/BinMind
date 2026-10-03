"""Multi-tool UAF comparison on 12-sample temporal-path benchmark."""
import sys, os, json, time, subprocess, re

# 从 deemo/ 目录运行时需要添加路径
_deemo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', '..'))
if _deemo_root not in sys.path:
    sys.path.insert(0, _deemo_root)

from modules.vuln.src.uaf.drift_orchestrator import analyze_uaf


def detect_same_reg(binary_path):
    """Same-register baseline: free(arg_reg) 后同一寄存器解引用 -> UAF."""
    proc = subprocess.run(['objdump', '-d', '-M', 'intel', binary_path],
        capture_output=True, text=True, timeout=30, encoding='utf-8', errors='replace')
    lines = proc.stdout.split('\n')

    findings = []
    free_regs = {}

    for i, line in enumerate(lines):
        il = line.strip().lower()
        if re.search(r'call\s+.*(?:free|kfree|delete)\b', il):
            for j in range(i-1, max(i-4, -1), -1):
                prev = lines[j].strip().lower()
                m = re.search(r'\bmov\s+(rdi|rcx),\s*(\w+)', prev)
                if m:
                    free_regs[i] = m.group(2)
                    break

    deref_pat = re.compile(
        r'\bmov\s+\w+,\s*(?:dword|qword|word|byte)(?:\s+ptr)?\s+\[(\w+)')
    for i, line in enumerate(lines):
        il = line.strip().lower()
        m = deref_pat.search(il)
        if m:
            base_reg = m.group(1)
            for fline in sorted(free_regs.keys(), reverse=True):
                if fline < i and free_regs[fline] == base_reg:
                    findings.append({
                        'free_line': fline, 'use_line': i, 'reg': base_reg})
                    break

    return {'uaf_count': len(findings), 'df_count': 0, 'findings': findings}


def detect_pattern(binary_path):
    """Pattern-match baseline: free后第一个解引用 -> UAF."""
    proc = subprocess.run(['objdump', '-d', '-M', 'intel', binary_path],
        capture_output=True, text=True, timeout=30, encoding='utf-8', errors='replace')
    lines = proc.stdout.split('\n')

    findings = []
    free_lines = []
    deref_pat = re.compile(
        r'\bmov\s+\w+,\s*(?:dword|qword|word|byte)(?:\s+ptr)?\s+\[(\w+)')

    for i, line in enumerate(lines):
        il = line.strip().lower()
        if re.search(r'call\s+.*(?:free|kfree|delete)\b', il):
            free_lines.append(i)

    for fline in free_lines:
        for j in range(fline + 1, min(fline + 50, len(lines))):
            il = lines[j].strip().lower()
            m = deref_pat.search(il)
            if m and m.group(1) not in ('rip', 'rsp', 'rbp'):
                findings.append({
                    'free_line': fline, 'use_line': j, 'reg': m.group(1)})
                break

    return {'uaf_count': len(findings), 'df_count': 0, 'findings': findings}


def compute_metrics(name, results, gt, times):
    tp = fp = tn = fn = 0
    for sample, (exp_uaf, exp_df, cat) in gt.items():
        r = results.get(sample, {})
        d = r.get('uaf_count', 0) + r.get('df_count', 0)
        gt_has = (exp_uaf + exp_df) > 0
        pred_has = d > 0
        if gt_has and pred_has: tp += 1
        elif gt_has and not pred_has: fn += 1
        elif not gt_has and pred_has: fp += 1
        else: tn += 1

    p = tp / max(1, tp + fp)
    r = tp / max(1, tp + fn)
    f1 = 2 * p * r / max(0.001, p + r)
    return name, tp, fp, tn, fn, p, r, f1, sum(times.values()) * 1000


def main():
    sample_dir = os.path.join(os.path.dirname(__file__), 'samples')
    ground_truth = {
        'sample_uaf_01_simple': (1, 0, 'simple'),
        'sample_uaf_02_reg_overwrite': (0, 0, 'safe_fp'),
        'sample_uaf_03_conditional': (1, 0, 'conditional'),
        'sample_uaf_04_alias': (1, 0, 'cross_fn'),
        'sample_uaf_05_multi_obj': (0, 0, 'safe_multi'),
        'sample_uaf_06_cross_fn': (1, 0, 'cross_fn'),
        'sample_uaf_07_double_free': (1, 1, 'double_free'),
        'sample_uaf_08_realloc': (1, 0, 'cross_fn'),
        'sample_uaf_09_safe_stack': (0, 0, 'safe_no_heap'),
        'sample_uaf_10_safe_no_free': (0, 0, 'safe_no_free'),
        'sample_uaf_11_struct_field': (1, 0, 'cross_fn'),
        'sample_uaf_12_loop': (1, 0, 'conditional'),
    }

# DRIFT (full pipeline)
    drift_results = {}
    drift_times = {}
    for name in ground_truth:
        path = os.path.join(sample_dir, name + '.exe')
        t0 = time.time()
        r = analyze_uaf(path)
        drift_times[name] = time.time() - t0

        uaf = 0; df = 0
        for f in r.findings:
            tv = f.get('temporal_verified', False)
            dfv = f.get('double_free_verified', False)
            ts = f.get('temporal_skipped', False)
            d = f.get('decision', '')
            if tv or dfv:
                uaf += 1
                if dfv: df += 1
            elif ts: continue
            elif d in ('confirmed_uaf', 'likely_uaf') and d != 'temporal_filtered':
                uaf += 1
        drift_results[name] = {'uaf_count': uaf, 'df_count': df}

# Baseline tools
    samereg_results = {}; samereg_times = {}
    pattern_results = {}; pattern_times = {}
    for name in ground_truth:
        path = os.path.join(sample_dir, name + '.exe')

        t0 = time.time()
        samereg_results[name] = detect_same_reg(path)
        samereg_times[name] = time.time() - t0

        t0 = time.time()
        pattern_results[name] = detect_pattern(path)
        pattern_times[name] = time.time() - t0

    drift_m = compute_metrics('DRIFT+Temporal', drift_results, ground_truth, drift_times)
    samereg_m = compute_metrics('SameReg', samereg_results, ground_truth, samereg_times)
    pattern_m = compute_metrics('PatternMatch', pattern_results, ground_truth, pattern_times)

    # Print comparison table
    print(f'\n{"="*80}')
    print(f'  Multi-Tool UAF Detection Comparison (12-sample benchmark)')
    print(f'{"="*80}')
    print(f'  {"Tool":<20} {"Prec":>8} {"Recall":>8} {"F1":>8} {"TP":>4} {"FP":>4} {"TN":>4} {"FN":>4}  {"Time":>8}')
    print(f'  {"-"*20} {"-"*8} {"-"*8} {"-"*8} {"-"*4} {"-"*4} {"-"*4} {"-"*4}  {"-"*8}')
    for m in [drift_m, samereg_m, pattern_m]:
        print(f'  {m[0]:<20} {m[5]:>7.1%} {m[6]:>7.1%} {m[7]:>7.3f} {m[1]:>4} {m[2]:>4} {m[3]:>4} {m[4]:>4}  {m[8]:>7.0f}ms')

    # Per-sample detail
    print(f'\n  Per-Sample Detail (* = misclassification):')
    print(f'  {"Sample":<35} {"GT":>4} {"DRIFT":>6} {"SameReg":>8} {"Pattern":>8}')
    for name, (exp_uaf, exp_df, cat) in ground_truth.items():
        d = drift_results[name]['uaf_count'] + drift_results[name]['df_count']
        s = samereg_results[name]['uaf_count'] + samereg_results[name]['df_count']
        p = pattern_results[name]['uaf_count'] + pattern_results[name]['df_count']
        exp = exp_uaf + exp_df
        dm = '*' if (d > 0) != (exp > 0) else ' '
        sm = '*' if (s > 0) != (exp > 0) else ' '
        pm = '*' if (p > 0) != (exp > 0) else ' '
        print(f'  {name:<35} {exp:>4} {d:>5}{dm} {s:>7}{sm} {p:>7}{pm}')

    # Save JSON
    out_path = os.path.join(os.path.dirname(__file__), 'multi_tool_comparison_12.json')
    with open(out_path, 'w') as f:
        json.dump({
            'drift': {'tp': drift_m[1], 'fp': drift_m[2], 'tn': drift_m[3], 'fn': drift_m[4],
                      'precision': drift_m[5], 'recall': drift_m[6], 'f1': drift_m[7],
                      'time_ms': drift_m[8]},
            'samereg': {'tp': samereg_m[1], 'fp': samereg_m[2], 'tn': samereg_m[3], 'fn': samereg_m[4],
                        'precision': samereg_m[5], 'recall': samereg_m[6], 'f1': samereg_m[7],
                        'time_ms': samereg_m[8]},
            'pattern': {'tp': pattern_m[1], 'fp': pattern_m[2], 'tn': pattern_m[3], 'fn': pattern_m[4],
                        'precision': pattern_m[5], 'recall': pattern_m[6], 'f1': pattern_m[7],
                        'time_ms': pattern_m[8]},
            'per_sample': {
                name: {
                    'drift': drift_results[name],
                    'samereg': samereg_results[name],
                    'pattern': pattern_results[name],
                }
                for name in ground_truth
            },
        }, f, indent=2)
    print(f'\nSaved: {out_path}')


if __name__ == '__main__':
    main()
