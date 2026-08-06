"""对比实验启动脚本 — 统一调度 Angr/QEMU/Ghidra/BinMind."""

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List

from compare.common import ExperimentResult, compute_metrics

BINARIES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                            'tests', 'regression', 'binaries')
RESULTS_DIR = os.path.join(os.path.dirname(__file__), 'results')


def find_binaries() -> List[str]:
    """查找所有待测 ELF 文件 (选 O2 优化版本)."""
    root = Path(BINARIES_DIR)
    if not root.exists():
        return []
    return sorted(str(p) for p in root.glob('*_O2') if p.is_file())


def run_angr(binary_path: str) -> ExperimentResult:
    """Angr exploration 做漏洞点分析."""
    start = time.time()
    try:
        result = subprocess.run(
            [sys.executable, '-m', 'experiments.compare.run_angr', binary_path],
            capture_output=True, text=True, timeout=120)
        elapsed = time.time() - start
        if result.returncode == 0:
            data = json.loads(result.stdout)
            return ExperimentResult(
                tool_name='Angr', sample_name=os.path.basename(binary_path),
                vulns_found=data.get('vulns_found', 0),
                elapsed_sec=round(elapsed, 2), success=True)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        pass
    return ExperimentResult(
        tool_name='Angr', sample_name=os.path.basename(binary_path),
        elapsed_sec=time.time()-start, success=False,
        error_msg='timeout or failed')


def run_ghidra(binary_path: str) -> ExperimentResult:
    """Ghidra headless 脚本分析."""
    start = time.time()
    try:
        result = subprocess.run(
            [sys.executable, '-m', 'experiments.compare.run_ghidra', binary_path],
            capture_output=True, text=True, timeout=120)
        elapsed = time.time() - start
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout)
            return ExperimentResult(
                tool_name='Ghidra', sample_name=os.path.basename(binary_path),
                vulns_found=data.get('vulns_found', 0),
                elapsed_sec=round(elapsed, 2), success=True)
    except (subprocess.TimeoutExpired, json.JSONDecodeError):
        pass
    return ExperimentResult(
        tool_name='Ghidra', sample_name=os.path.basename(binary_path),
        elapsed_sec=time.time()-start, success=False,
        error_msg='timeout or failed')


def run_binmind(binary_path: str) -> ExperimentResult:
    """BinMind 自身的 taint + heap 检测."""
    start = time.time()
    try:
        from tests.regression.run.scan_runner import scan_with_taint_detector
        r = scan_with_taint_detector(binary_path)
        elapsed = time.time() - start
        return ExperimentResult(
            tool_name='BinMind', sample_name=os.path.basename(binary_path),
            vulns_found=r.vulns_found,
            vulns_list=[v.get('func', '') for v in r.vulns],
            elapsed_sec=round(elapsed, 2), success=True)
    except Exception as e:
        return ExperimentResult(
            tool_name='BinMind', sample_name=os.path.basename(binary_path),
            elapsed_sec=time.time()-start, success=False,
            error_msg=str(e)[:100])


def run_all() -> Dict[str, dict]:
    """运行全部对比实验."""
    os.makedirs(RESULTS_DIR, exist_ok=True)
    binaries = find_binaries()
    if not binaries:
        print('No binaries found. Run build_samples.py first.')
        return {}

    all_results = []
    for bpath in binaries[:10]:  # 限制 10 个避免过长时间
        print(f'  Testing {os.path.basename(bpath)}...')
        for runner in [run_binmind, run_angr, run_ghidra]:
            r = runner(bpath)
            all_results.append(r)
            status = 'OK' if r.success else 'FAIL'
            print(f'    [{status}] {r.tool_name}: {r.vulns_found} vulns, '
                  f'{r.elapsed_sec:.1f}s')

    # 按工具分组计算指标
    by_tool = {}
    for tool in ['BinMind', 'Angr', 'Ghidra']:
        tool_results = [r for r in all_results if r.tool_name == tool]
        metrics = compute_metrics(tool_results)
        metrics['success_rate'] = sum(1 for r in tool_results if r.success) / max(1, len(tool_results))
        by_tool[tool] = metrics

    # 保存为 JSON
    output = {'by_tool': by_tool, 'n_binaries_tested': len(binaries)}
    with open(os.path.join(RESULTS_DIR, 'comparison.json'), 'w') as f:
        json.dump(output, f, indent=2)

    return by_tool


if __name__ == '__main__':
    print('Running comparison experiment...')
    results = run_all()
    for tool, metrics in results.items():
        print(f'{tool}: F1={metrics.get("F1", 0):.3f}, '
              f'avg_time={metrics.get("avg_time_s", 0):.1f}s')
