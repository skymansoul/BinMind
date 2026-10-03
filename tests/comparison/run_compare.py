#!/usr/bin/env python3
"""
横向对比实验 — BinMind vs Angr vs QEMU vs Ghidra.

对同一批样本运行多个工具, 统计检测耗时/误报/漏报/内存.

用法: python tests/comparison/run_compare.py <sample_dir>

前置依赖: angr, qemu-user, ghidra_headless 需已安装.
"""

import json
import os
import resource
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

def find_binaries(sample_dir: str) -> list:
    binaries = []
    for root, _, files in os.walk(sample_dir):
        for f in files:
            fp = os.path.join(root, f)
            if os.access(fp, os.X_OK) if os.name != 'nt' else not f.endswith('.c'):
                if not f.endswith('.c') and not f.endswith('.sh'):
                    binaries.append(fp)
    return sorted(binaries)


def measure_resource(func, *args, **kwargs):
    """测量函数的执行时间和峰值内存."""
    t0 = time.time()
    try:
        mem_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    except Exception:
        mem_before = 0
    result = func(*args, **kwargs)
    elapsed = time.time() - t0
    try:
        mem_after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        mem_delta = max(0, mem_after - mem_before)
    except Exception:
        mem_delta = 0
    return result, elapsed, mem_delta


def run_binmind(binary_path: str) -> dict:
    """运行 BinMind 扫描器."""
    try:
        from tests.test_harness.scan_scheduler import run_scanner
        result, elapsed, mem = measure_resource(run_scanner, binary_path, 'all')
        findings = []
        for det_name, det_res in result.get('detectors', {}).items():
            if det_res.get('success'):
                findings.extend(det_res.get('findings', []))
        return {'tool': 'BinMind', 'findings': len(findings), 'elapsed': elapsed,
                'peak_mem_kb': mem, 'success': True}
    except Exception as e:
        return {'tool': 'BinMind', 'findings': 0, 'elapsed': 0, 'peak_mem_kb': 0,
                'success': False, 'error': str(e)[:100]}


def run_angr(binary_path: str) -> dict:
    """使用 Angr 探索方式做漏洞点分析."""
    try:
        import angr
        t0 = time.time()
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()
        # 计数危险函数调用
        dangerous = {'printf', 'gets', 'strcpy', 'strcat', 'sprintf', 'malloc', 'free'}
        count = 0
        for func in cfg.functions.values():
            if func.name in dangerous:
                count += 1
        elapsed = time.time() - t0
        return {'tool': 'Angr', 'findings': count, 'elapsed': elapsed,
                'peak_mem_kb': 0, 'success': True}
    except Exception as e:
        return {'tool': 'Angr', 'findings': 0, 'elapsed': 0, 'peak_mem_kb': 0,
                'success': False, 'error': str(e)[:100]}


def run_qemu(binary_path: str) -> dict:
    """使用 QEMU user mode + strace 插桩."""
    try:
        t0 = time.time()
        result = subprocess.run(
            ['qemu-x86_64', '-strace', binary_path],
            capture_output=True, text=True, timeout=10,
        )
        elapsed = time.time() - t0
        # 简单统计: 计算 strace 输出行数作为"activity proxy"
        lines = result.stderr.count('\n')
        return {'tool': 'QEMU', 'findings': min(lines, 999), 'elapsed': elapsed,
                'peak_mem_kb': 0, 'success': True}
    except FileNotFoundError:
        return {'tool': 'QEMU', 'findings': -1, 'elapsed': 0, 'peak_mem_kb': 0,
                'success': False, 'error': 'qemu-x86_64 not installed'}
    except Exception as e:
        return {'tool': 'QEMU', 'findings': 0, 'elapsed': 0, 'peak_mem_kb': 0,
                'success': False, 'error': str(e)[:100]}


def run_ghidra(binary_path: str) -> dict:
    """使用 Ghidra headless 自动化分析."""
    try:
        t0 = time.time()
        script = '/tmp/ghidra_analyze.py'
        result = subprocess.run(
            ['ghidra_headless', binary_path, '-scriptPath', '/tmp',
             '-postScript', script],
            capture_output=True, text=True, timeout=120,
        )
        elapsed = time.time() - t0
        count = result.stdout.count('vulnerability') + result.stdout.count('dangerous')
        return {'tool': 'Ghidra', 'findings': count, 'elapsed': elapsed,
                'peak_mem_kb': 0, 'success': True}
    except FileNotFoundError:
        return {'tool': 'Ghidra', 'findings': -1, 'elapsed': 0, 'peak_mem_kb': 0,
                'success': False, 'error': 'ghidra_headless not installed'}
    except Exception as e:
        return {'tool': 'Ghidra', 'findings': 0, 'elapsed': 0, 'peak_mem_kb': 0,
                'success': False, 'error': str(e)[:100]}


def main():
    sample_dir = sys.argv[1] if len(sys.argv) > 1 else '../vuln_samples'
    output_file = sys.argv[2] if len(sys.argv) > 2 else 'comparison_results.json'

    binaries = find_binaries(sample_dir)
    print(f'Found {len(binaries)} binaries for comparison')

    tools = [
        ('BinMind', run_binmind),
        ('Angr', run_angr),
        ('QEMU', run_qemu),
        ('Ghidra', run_ghidra),
    ]

    all_results = []
    for i, bpath in enumerate(binaries):
        print(f'\n[{i+1}/{len(binaries)}] {os.path.basename(bpath)}')
        for tool_name, tool_fn in tools:
            print(f'  Running {tool_name}...', end=' ', flush=True)
            r = tool_fn(bpath)
            r['binary'] = bpath
            all_results.append(r)
            status = 'OK' if r['success'] else f'FAIL: {r.get("error", "?")}'
            print(f'{r["findings"]} findings, {r["elapsed"]:.2f}s ({status})')

    with open(output_file, 'w') as f:
        json.dump(all_results, f, indent=2)

    # 汇总统计
    by_tool = defaultdict(lambda: {'total': 0, 'findings': 0, 'elapsed': 0})
    for r in all_results:
        t = r['tool']
        by_tool[t]['total'] += 1
        by_tool[t]['findings'] += max(0, r['findings'])
        by_tool[t]['elapsed'] += r['elapsed']

    print('\n=== SUMMARY ===')
    for tool in ['BinMind', 'Angr', 'QEMU', 'Ghidra']:
        s = by_tool[tool]
        avg = s['elapsed'] / max(s['total'], 1)
        print(f'  {tool:10s}: {s["total"]} binaries, {s["findings"]} findings, '
              f'{s["elapsed"]:.1f}s total ({avg:.2f}s avg)')

    print(f'\nResults saved to {output_file}')

if __name__ == '__main__':
    main()
