#!/usr/bin/env python3
# coding: utf-8
"""
样本批量编译模块 — 遍历 samples/ 下所有目录, 执行 make 编译.
输出编译状态和各样本的 ELF 路径列表.
"""

import os, subprocess, json, sys
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class CompileResult:
    sample_dir: str
    success: bool
    elf_path: str = ''
    error: str = ''
    make_output: str = ''


def find_samples(samples_root: str) -> List[str]:
    """扫描 samples/ 下所有包含 Makefile 的子目录."""
    root = Path(samples_root)
    if not root.exists():
        raise FileNotFoundError(f'样本目录不存在: {samples_root}')
    dirs = sorted([
        str(d) for d in root.iterdir()
        if d.is_dir() and (d / 'Makefile').exists()
    ])
    return dirs


def compile_sample(sample_dir: str, cc: str = 'gcc') -> CompileResult:
    """编译单个样本目录. 使用 make 但追加 CC 环境变量."""
    result = CompileResult(sample_dir=sample_dir)
    try:
        env = os.environ.copy()
        env['CC'] = cc
        proc = subprocess.run(
            ['make', '-C', sample_dir, 'clean'],
            capture_output=True, text=True, timeout=30, env=env,
        )
        proc = subprocess.run(
            ['make', '-C', sample_dir],
            capture_output=True, text=True, timeout=30, env=env,
        )
        result.make_output = proc.stdout + proc.stderr
        if proc.returncode != 0:
            result.success = False
            result.error = f'make 返回码 {proc.returncode}: {proc.stderr[:200]}'
            return result

        # 查找生成的 ELF
        for f in os.listdir(sample_dir):
            if f.endswith('.elf') or (os.access(os.path.join(sample_dir, f), os.X_OK)
                                       and '.' not in f.replace('_', '')):
                full = os.path.join(sample_dir, f)
                if os.path.isfile(full) and os.access(full, os.X_OK):
                    result.elf_path = full
                    result.success = True
                    return result

        result.success = False
        result.error = '编译成功但未找到输出 ELF'
    except subprocess.TimeoutExpired:
        result.success = False
        result.error = '编译超时'
    except FileNotFoundError:
        result.success = False
        result.error = 'make 或 gcc 未安装'
    except Exception as e:
        result.success = False
        result.error = str(e)
    return result


def compile_all(samples_root: str, cc: str = 'gcc',
                output_json: Optional[str] = None) -> Tuple[
                    List[CompileResult], Dict[str, Any]]:
    """编译所有样本, 返回结果列表和摘要."""
    sample_dirs = find_samples(samples_root)
    results = []
    success_count = 0
    for d in sample_dirs:
        r = compile_sample(d, cc)
        results.append(r)
        if r.success:
            success_count += 1

    summary = {
        'total': len(sample_dirs),
        'success': success_count,
        'failed': len(sample_dirs) - success_count,
        'elf_paths': [r.elf_path for r in results if r.success],
        'errors': [{'dir': r.sample_dir, 'error': r.error}
                   for r in results if not r.success],
    }

    if output_json:
        with open(output_json, 'w') as f:
            json.dump(summary, f, indent=2, default=str)

    return results, summary


if __name__ == '__main__':
    root = os.environ.get('SAMPLE_ROOT',
                          os.path.join(os.path.dirname(__file__), '..', 'samples'))
    results, summary = compile_all(root)
    print(json.dumps(summary, indent=2, default=str))
    sys.exit(0 if summary['failed'] == 0 else 1)
