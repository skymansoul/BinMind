"""
编译模块: 批量编译 C 样本为 ELF 二进制。

支持三种编译配置:
  default    — 标准 gcc 编译
  no_mitigation — -fno-stack-protector -z execstack
  asan       — -fsanitize=address (ASAN 插桩)

每样本三配置 → 最多 30 个编译产物。
"""

import os
import subprocess
import sys
from dataclasses import dataclass, field
from typing import List, Optional

_SAMPLE_ROOT = os.path.join(os.path.dirname(__file__), 'samples')


@dataclass
class BuildResult:
    sample_id: str
    config: str           # "default" | "no_mitigation" | "asan"
    binary_path: Optional[str] = None
    success: bool = False
    error_msg: str = ""

    @property
    def binary_size(self) -> int:
        if self.binary_path and os.path.isfile(self.binary_path):
            return os.path.getsize(self.binary_path)
        return 0


_BUILD_CONFIGS = [
    ('default',        'gcc -o {out} {src}'),
    ('no_mitigation',  'gcc -o {out} {src} -fno-stack-protector -z execstack'),
    ('asan',           'gcc -o {out} {src} -fsanitize=address -g -O0'),
]


def find_sample_dirs(root: Optional[str] = None) -> List[str]:
    """扫描 samples/ 目录下所有包含 vuln.c 的子目录。"""
    root = root or _SAMPLE_ROOT
    dirs = []
    for dirpath, _, filenames in os.walk(root):
        if 'vuln.c' in filenames:
            dirs.append(dirpath)
    return sorted(dirs)


def build_sample(src_dir: str, output_dir: str) -> List[BuildResult]:
    """
    编译单个样本的三种配置。

    src_dir: 包含 vuln.c 的目录
    output_dir: 编译产物输出目录
    """
    src_file = os.path.join(src_dir, 'vuln.c')
    if not os.path.isfile(src_file):
        return [BuildResult(os.path.basename(src_dir), 'default',
                           error_msg=f"source not found: {src_file}")]

    sample_id = os.path.basename(src_dir)
    os.makedirs(output_dir, exist_ok=True)
    results = []

    for config_name, cmd_template in _BUILD_CONFIGS:
        out_name = f"{sample_id}_{config_name}"
        out_path = os.path.join(output_dir, out_name)
        cmd = cmd_template.format(out=out_path, src=src_file)
        try:
            subprocess.run(cmd, shell=True, capture_output=True,
                          timeout=30, check=True)
            results.append(BuildResult(sample_id, config_name, out_path, True))
        except subprocess.CalledProcessError as e:
            # ASAN 在某些系统上不可用, 不算致命错误
            stderr = e.stderr.decode('utf-8', errors='replace')[:120]
            results.append(BuildResult(sample_id, config_name,
                           error_msg=f"gcc failed: {stderr}"))
        except subprocess.TimeoutExpired:
            results.append(BuildResult(sample_id, config_name,
                           error_msg="compilation timeout"))

    return results


def build_all(output_dir: Optional[str] = None) -> List[BuildResult]:
    """编译所有样本。返回全部 BuildResult。"""
    output_dir = output_dir or os.path.join(os.path.dirname(__file__), 'results', 'binaries')
    os.makedirs(output_dir, exist_ok=True)

    sample_dirs = find_sample_dirs()
    all_results = []
    for d in sample_dirs:
        results = build_sample(d, output_dir)
        all_results.extend(results)
        ok = sum(1 for r in results if r.success)
        print(f"  {os.path.basename(d)}: {ok}/{len(results)} built")
    return all_results


if __name__ == '__main__':
    print(f"Building {len(find_sample_dirs())} samples...")
    results = build_all()
    ok = sum(1 for r in results if r.success)
    print(f"Done: {ok}/{len(results)} binaries compiled")
