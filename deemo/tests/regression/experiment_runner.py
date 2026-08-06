"""
对比实验统管脚本 —— 对同一样本集运行 BinMind + Angr + QEMU + Ghidra,
收集各工具指标, 生成 JSON 数据文件供绘图和 LaTeX 表格使用。
"""

import os, sys, json, time, subprocess, argparse

_PROJ = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, _PROJ)
sys.path.insert(0, os.path.dirname(__file__))


def run_experiment(binary_dir: str, output_file: str) -> dict:
    """运行全部对比实验。"""
    binaries = []
    for root, _, files in os.walk(binary_dir):
        for f in files:
            fpath = os.path.join(root, f)
            if os.access(fpath, os.X_OK) or ('vuln' in f and '.' not in f[len('vuln'):]):
                binaries.append(fpath)

    results = {
        'binmind': [], 'angr': [], 'qemu': [], 'ghidra': [],
        'binary_count': len(binaries), 'timestamp': time.time(),
    }

    # BinMind
    print("[1/4] BinMind scan...")
    from scan_scheduler import ScanScheduler
    scheduler = ScanScheduler(timeout_sec=30)
    for bpath in binaries:
        sid = os.path.basename(os.path.dirname(bpath))
        sr = scheduler.scan_binary(bpath, sid)
        results['binmind'].append({
            'sample': sid, 'elapsed_ms': sr.elapsed_ms,
            'stack_found': sr.stack_overflow_found,
            'fmt_found': sr.format_string_found,
            'uaf_found': sr.uaf_found,
            'heap_found': sr.heap_overflow_found,
            'success': sr.success, 'error': sr.error_msg,
        })

    # Angr
    print("[2/4] Angr analysis...")
    from compare_angr import analyze_with_angr
    for bpath in binaries:
        ar = analyze_with_angr(bpath, timeout=60)
        results['angr'].append({
            'sample': os.path.basename(os.path.dirname(bpath)),
            'elapsed_ms': ar['elapsed_ms'],
            'findings_count': len(ar['findings']),
            'error': ar['error'],
        })

    # QEMU
    print("[3/4] QEMU trace...")
    from compare_qemu import trace_with_qemu
    for bpath in binaries[:5]:  # QEMU 慢, 只跑前 5 个
        qr = trace_with_qemu(bpath, timeout=30)
        results['qemu'].append({
            'sample': os.path.basename(os.path.dirname(bpath)),
            'elapsed_ms': qr['elapsed_ms'],
            'mem_accesses': len(qr['memory_accesses']),
            'error': qr['error'],
        })

    # Ghidra
    print("[4/4] Ghidra analysis...")
    from compare_ghidra import analyze_with_ghidra
    for bpath in binaries[:5]:  # Ghidra 慢, 只跑前 5 个
        gr = analyze_with_ghidra(bpath, timeout=120)
        results['ghidra'].append({
            'sample': os.path.basename(os.path.dirname(bpath)),
            'elapsed_ms': gr['elapsed_ms'],
            'findings_count': len(gr['findings']),
            'error': gr['error'],
        })

    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"Results saved to {output_file}")
    return results


def compute_summary(results: dict) -> dict:
    """从原始结果计算汇总指标。"""
    summary = {}
    for tool in ['binmind', 'angr', 'qemu', 'ghidra']:
        entries = results.get(tool, [])
        if not entries:
            summary[tool] = {'avg_time_ms': 0, 'total_findings': 0,
                             'success_rate': 0, 'sample_count': 0}
            continue
        ok = sum(1 for e in entries if e.get('success', True))
        times = [e['elapsed_ms'] for e in entries]
        findings = sum(e.get('findings_count', e.get('heap_found', 0))
                      for e in entries)
        summary[tool] = {
            'avg_time_ms': round(sum(times) / len(times), 1),
            'total_findings': findings,
            'success_rate': round(ok / len(entries), 3),
            'sample_count': len(entries),
        }
    return summary


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--binary-dir', default=os.path.join(
        os.path.dirname(__file__), 'results', 'binaries'))
    ap.add_argument('--output', default=os.path.join(
        os.path.dirname(__file__), 'results', 'experiment_results.json'))
    args = ap.parse_args()

    if not os.path.isdir(args.binary_dir):
        print(f"Binary dir not found: {args.binary_dir}")
        print("Run 'python build_samples.py' first")
        sys.exit(1)

    results = run_experiment(args.binary_dir, args.output)
    summary = compute_summary(results)
    print(json.dumps(summary, indent=2))
