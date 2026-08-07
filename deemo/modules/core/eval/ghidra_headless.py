#!/usr/bin/env python3
# coding: utf-8
"""
Ghidra 无头分析脚本 — 自动反编译并标记危险函数调用点.

需要 Ghidra 已安装并设定 GHIDRA_INSTALL_DIR 环境变量.
调用 Ghidra 的 Headless Analyzer 执行预写的 Java 脚本,
收集反编译结果中识别出的危险函数调用.

Ghidra 脚本路径: ghidra_scripts/FindHeapOverflow.java (与本文同级)
"""

import os, sys, json, time, subprocess, tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional


def _find_ghidra_headless() -> Optional[str]:
    """查找 Ghidra Headless Analyzer 路径."""
    install_dir = os.environ.get('GHIDRA_INSTALL_DIR', '')
    candidates = []
    if install_dir:
        candidates = [
            os.path.join(install_dir, 'support', 'analyzeHeadless'),
            os.path.join(install_dir, 'support', 'analyzeHeadless.bat'),
        ]
    # 常见安装路径
    candidates += [
        '/opt/ghidra/support/analyzeHeadless',
        '/usr/local/ghidra/support/analyzeHeadless',
        os.path.expanduser('~/ghidra/support/analyzeHeadless'),
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return None


def analyze_with_ghidra(elf_path: str,
                        ghidra_project_dir: Optional[str] = None,
                        timeout_s: int = 300) -> Dict[str, Any]:
    """使用 Ghidra 对 ELF 进行无头分析.

    返回格式与其他工具一致: {sample_id, candidates, wall_time_s, mem_mb, ...}
    """
    result = {
        'sample_id': os.path.basename(elf_path).replace('.elf', ''),
        'elf_path': elf_path,
        'success': False,
        'candidates': 0,
        'heap_overflow_candidates': 0,
        'dangerous_functions_found': [],
        'wall_time_s': 0.0,
        'mem_peak_mb': 0.0,
        'error': '',
    }

    t0 = time.perf_counter()
    headless = _find_ghidra_headless()
    if not headless:
        result['error'] = 'Ghidra headless analyzer 未找到, 请设置 GHIDRA_INSTALL_DIR'
        result['wall_time_s'] = time.perf_counter() - t0
        return result

    project_dir = ghidra_project_dir or tempfile.mkdtemp(prefix='ghidra_project_')

    try:
        # 构建 Ghidra 命令行
        script_dir = Path(__file__).resolve().parent / 'ghidra_scripts'
        script_path = script_dir / 'FindHeapOverflow.java'

        if not script_path.exists():
            # Ghidra 脚本不存在 → 使用内置的简单分析
            result = _fallback_ghidra_analysis(elf_path)
            result['wall_time_s'] = time.perf_counter() - t0
            return result

        cmd = [
            headless,
            project_dir,
            'TempProject',
            '-import', elf_path,
            '-scriptPath', str(script_dir),
            '-postScript', 'FindHeapOverflow.java',
            '-noanalysis',  # 加速: 跳过完整自动分析
        ]

        proc = subprocess.run(
            cmd,
            capture_output=True, text=True,
            timeout=timeout_s,
        )

        # 解析 Ghidra 脚本输出
        output = proc.stdout + proc.stderr
        for line in output.split('\n'):
            if 'HEAP_OVERFLOW_CANDIDATE:' in line:
                result['heap_overflow_candidates'] += 1
                result['dangerous_functions_found'].append(line.strip())
            elif 'DANGEROUS_CALL:' in line:
                result['candidates'] += 1

        result['success'] = True

    except subprocess.TimeoutExpired:
        result['error'] = f'Ghidra 分析超时 ({timeout_s}s)'
    except Exception as e:
        result['error'] = str(e)[:200]

    result['wall_time_s'] = round(time.perf_counter() - t0, 2)
    return result


def _fallback_ghidra_analysis(elf_path: str) -> Dict[str, Any]:
    """Ghidra 不可用时的回退分析 — 基于 objdump/readelf 的启发式."""
    result = {
        'sample_id': os.path.basename(elf_path).replace('.elf', ''),
        'success': False,
        'candidates': 0,
        'heap_overflow_candidates': 0,
        'dangerous_functions_found': [],
        'error': '',
    }
    try:
        # 使用 objdump 反汇编
        proc = subprocess.run(
            ['objdump', '-d', elf_path],
            capture_output=True, text=True, timeout=30,
        )
        disasm = proc.stdout
        # 简单启发式: 查找 call malloc 后紧跟 call memcpy 的模式
        lines = disasm.split('\n')
        found_alloc = False
        for line in lines:
            if 'call' in line and 'malloc' in line:
                found_alloc = True
            elif found_alloc and 'call' in line and any(
                f in line for f in ('memcpy', 'strcpy', 'memset', 'sprintf')):
                result['candidates'] += 1
                result['dangerous_functions_found'].append(line.strip())
                found_alloc = False
        result['success'] = True
    except Exception as e:
        result['error'] = str(e)[:200]
    return result


def ghidra_batch(elf_paths: List[str],
                 output_json: Optional[str] = None) -> List[Dict]:
    """批量 Ghidra 分析."""
    results = []
    for i, path in enumerate(elf_paths):
        print(f'[{i+1}/{len(elf_paths)}] Ghidra analyzing {os.path.basename(path)} ...')
        r = analyze_with_ghidra(path)
        results.append(r)
    if output_json:
        with open(output_json, 'w') as f:
            json.dump(results, f, indent=2, default=str)
    return results


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('elf_paths', nargs='+')
    ap.add_argument('--output')
    ap.add_argument('--project-dir')
    args = ap.parse_args()
    ghidra_batch(args.elf_paths, args.output)
