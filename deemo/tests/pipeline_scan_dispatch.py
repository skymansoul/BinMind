"""
回归测试管道 — 扫描调度阶段。

封装 scan_binary 的批量调用逻辑,
管理扫描进度输出和错误恢复,
输出结构化扫描结果供结果收集阶段消费。
"""
import os
import sys
import time
from typing import List, Dict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE_DIR = os.path.join(BASE, 'tests', 'samples', 'heap_overflow')


def scan_single(binary_path: str, src_path: str, name: str) -> dict:
    """扫描单个二进制, 返回带样本名的结果。"""
    from tests.pipeline_scanner import scan_binary
    try:
        r = scan_binary(binary_path, src_path)
        r['sample'] = name
        return r
    except Exception as e:
        return {
            'sample': name,
            'detected': False,
            'findings_count': 0,
            'baseline_count': 0,
            'gapsbv_filtered': 0,
            'error': str(e)[:200],
            'duration_ms': 0,
        }


def scan_all(compile_results: list, sample_dir: str = None) -> Dict[str, dict]:
    """批量扫描所有编译成功的样本, 返回 {sample_name: scan_result}。"""
    sdir = sample_dir or SAMPLE_DIR
    scan_results = {}
    total = len(compile_results)

    for i, c in enumerate(compile_results):
        name = c['name']
        src_path = os.path.join(sdir, name, 'vuln.c')
        r = scan_single(c['binary'], src_path, name)
        scan_results[name] = r
        marker = '!' if r.get('detected') else ' '
        print(f'  [{i+1:2d}/{total}] {marker} {name}: '
              f'src={r.get("source_scan_count", 0)} '
              f'ovf={r.get("src_overflow", 0)} unc={r.get("src_uncertain", 0)} '
              f'safe={r.get("src_safe", 0)} gflt={r.get("guard_filtered", 0)}, '
              f'{r.get("duration_ms", 0)}ms')

    return scan_results


def scan_failed_placeholder(failed_compiles: list) -> Dict[str, dict]:
    """为编译失败的样本生成占位结果, 保持结果集完整。"""
    placeholders = {}
    for b in failed_compiles:
        placeholders[b['name']] = {
            'detected': False,
            'findings_count': 0,
            'baseline_count': 0,
            'gapsbv_filtered': 0,
            'error': f'compile failed: {b.get("error", "")[:100]}',
        }
    return placeholders


if __name__ == '__main__':
    from tests.pipeline_compile import compile_all_samples, print_compile_summary
    print('=' * 60)
    print('扫描调度阶段')
    print('=' * 60)
    results = compile_all_samples()
    ok, bad = print_compile_summary(results)
    print(f'\n扫描 {len(ok)} 个二进制...')
    scan_results = scan_all(ok)
    scan_results.update(scan_failed_placeholder(bad))
    print(f'\n扫描完成: {len(scan_results)} 个结果')
