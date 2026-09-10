"""CVE 样本编译模块 — 统一编译脚本 + 多优化级别.

用途: 自动编译 tests/regression/samples/ 下的所有 CVE 样本源码,
      生成未加壳 (O0/O2/Os) 和加壳 (UPX) 两个版本的 ELF 文件。

设计决策:
  - O0: 无优化, 保留源码结构, 用于验证基本检测能力
  - O2: 标准优化, 内联/死代码消除, 考验跨函数检测
  - Os: 体积优化, 指令序列变化最大, 考验 IR 层面的鲁棒性
  - UPX: 加壳变体, 检测是否因压缩壳而完全失效
"""

import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple


OPT_LEVELS = ['O0', 'O2', 'Os']
STRIP_BINARIES = True


@dataclass
class BuildResult:
    sample_name: str
    opt_level: str
    binary_path: str
    success: bool
    error_msg: str = ''


def find_samples(samples_dir: str) -> List[Tuple[str, str]]:
    """扫描 samples/ 目录, 返回 [(名称, 源码路径), ...]."""
    samples = []
    root = Path(samples_dir)
    if not root.exists():
        return samples
    for item in sorted(root.iterdir()):
        if item.is_dir():
            c_files = list(item.glob('*.c'))
            if c_files:
                samples.append((item.name, str(c_files[0])))
    return samples


def compile_sample(name: str, src_path: str, opt: str,
                   output_dir: str) -> BuildResult:
    """编译单个样本."""
    os.makedirs(output_dir, exist_ok=True)
    binary_name = f'{name}_{opt}'
    binary_path = os.path.join(output_dir, binary_name)

    cmd = ['gcc', f'-{opt}', '-o', binary_path, src_path]
    if STRIP_BINARIES:
        cmd.insert(1, '-s')

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0 and os.path.isfile(binary_path):
            return BuildResult(name, opt, binary_path, True)
        return BuildResult(name, opt, '', False, result.stderr[:200])
    except subprocess.TimeoutExpired:
        return BuildResult(name, opt, '', False, 'compilation timeout')
    except FileNotFoundError:
        return BuildResult(name, opt, '', False, 'gcc not found')


def build_all(samples_dir: str, output_dir: str) -> List[BuildResult]:
    """编译所有样本 × 所有优化级别."""
    results = []
    samples = find_samples(samples_dir)
    for name, src_path in samples:
        for opt in OPT_LEVELS:
            r = compile_sample(name, src_path, opt, output_dir)
            results.append(r)
            status = 'OK' if r.success else 'FAIL'
            print(f'  [{status}] {name} -{opt}')
    return results


def try_upx_pack(binary_path: str) -> Optional[str]:
    """尝试 UPX 加壳."""
    packed = binary_path + '_upx'
    try:
        subprocess.run(['upx', '-q', '-o', packed, binary_path],
                       capture_output=True, timeout=60, check=True)
        if os.path.isfile(packed):
            return packed
    except (subprocess.CalledProcessError, FileNotFoundError,
            subprocess.TimeoutExpired):
        pass
    return None


def print_summary(results: List[BuildResult]) -> None:
    """打印编译结果摘要."""
    n_ok = sum(1 for r in results if r.success)
    n_fail = len(results) - n_ok
    print(f'\nBuild summary: {n_ok}/{len(results)} succeeded')
    for r in results:
        if not r.success:
            print(f'  FAIL {r.sample_name} -{r.opt_level}: {r.error_msg}')


if __name__ == '__main__':
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    samples = os.path.join(base_dir, 'samples')
    output = os.path.join(base_dir, 'binaries')
    print(f'Building samples from {samples}...')
    results = build_all(samples, output)
    print_summary(results)
