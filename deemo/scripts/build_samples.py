#!/usr/bin/env python3
"""
样本编译与注册脚本。

在 Linux/WSL 环境下编译教学样本，自动注册到 sample_manager。

用法:
  python scripts/build_samples.py                    # 编译全部教学样本
  python scripts/build_samples.py --dry-run          # 仅列出待编译样本
  python scripts/build_samples.py --register-only    # 仅注册已有二进制
"""

import argparse
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.sample_manager import SampleManager, init_sample_directories

SAMPLES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'samples')

# 教学样本配置: (目录, 文件名, 编译参数, 漏洞类型, 难度)
TEACHING_SAMPLES = [
    ('teaching/01_stack_overflow', 'vuln_stack_bof',
     ['gcc', '-fno-stack-protector', '-no-pie', '-o'],
     'stack-overflow', 'easy',
     'gets + no canary + no PIE = 直接 ret2libc'),
    ('teaching/02_format_string', 'vuln_fmtstr',
     ['gcc', '-o'],
     'format-string', 'medium',
     'printf(buf) + Full RELRO = 信息泄露路径'),
    ('teaching/03_heap_uaf', 'vuln_heap_uaf',
     ['gcc', '-o'],
     'heap-corruption', 'hard',
     'UAF + 函数指针覆盖 = 控制流劫持'),
    ('teaching/04_integer_overflow', 'vuln_int_overflow',
     ['gcc', '-o'],
     'integer-overflow', 'medium',
     'unsigned short overflow → malloc(0)'),
    ('teaching/05_command_injection', 'vuln_cmd_inj',
     ['gcc', '-o'],
     'command-injection', 'easy',
     'system() 直接拼接用户输入'),
    ('teaching/06_stack_overflow_canary', 'vuln_stack_canary',
     ['gcc', '-fstack-protector', '-no-pie', '-o'],
     'stack-overflow', 'medium',
     '栈溢出 + Canary 需先泄露'),
]


def find_gcc():
    """在 PATH 中查找可用的 C 编译器。"""
    for cc in ['gcc', 'cc', 'clang']:
        if subprocess.run(['which', cc], capture_output=True).returncode == 0:
            return cc
    return None


def compile_sample(src_dir, binary_name, cc, cc_flags):
    """编译单个教学样本。"""
    src_path = os.path.join(SAMPLES_DIR, src_dir, 'vuln.c')
    bin_path = os.path.join(SAMPLES_DIR, src_dir, binary_name)

    if not os.path.isfile(src_path):
        print(f'  SKIP: source not found: {src_path}')
        return None

    if os.path.isfile(bin_path) and os.path.getmtime(bin_path) > os.path.getmtime(src_path):
        print(f'  SKIP: binary is up to date: {binary_name}')
        return bin_path

    cmd = [cc] + cc_flags + [bin_path, src_path]
    print(f'  Compiling: {" ".join(cmd)}')
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        print(f'  OK: {binary_name}')
        return bin_path
    except subprocess.CalledProcessError as e:
        print(f'  FAIL: {binary_name}\n    {e.stderr.strip()}')
        return None


def main():
    parser = argparse.ArgumentParser(description='Build and register sample binaries')
    parser.add_argument('--dry-run', action='store_true',
                        help='List samples without building')
    parser.add_argument('--register-only', action='store_true',
                        help='Only register existing binaries')
    parser.add_argument('--cc', default=None, help='C compiler to use')
    args = parser.parse_args()

    cc = args.cc or find_gcc() or 'gcc'

    if args.dry_run:
        print('Samples to build:')
        for src_dir, bin_name, flags, vtype, diff, note in TEACHING_SAMPLES:
            print(f'  {src_dir}/{bin_name}  [{vtype}] {note}')
        return

    if not args.register_only:
        if cc == 'gcc' and subprocess.run(['which', 'gcc'],
                                          capture_output=True).returncode != 0:
            print('WARNING: gcc not found. Cross-compile or use WSL/Docker.')
            print('Proceeding with --register-only for any pre-built binaries.')
            args.register_only = True

    # 初始化样本目录
    init_sample_directories(SAMPLES_DIR)

    # 注册管理器
    mgr = SampleManager()

    for src_dir, bin_name, flags, vtype, diff, note in TEACHING_SAMPLES:
        full_dir = os.path.join(SAMPLES_DIR, src_dir)
        bin_path = os.path.join(full_dir, bin_name)

        if not args.register_only:
            bin_path = compile_sample(src_dir, bin_name, cc, flags) or bin_path

        if os.path.isfile(bin_path):
            try:
                sample_id = mgr.register(
                    bin_path,
                    vuln_type=vtype,
                    difficulty=diff,
                    source='teaching',
                    tags=['x86_64', vtype],
                    notes=note,
                )
                print(f'  Registered: {bin_name} (id={sample_id})')
            except Exception as e:
                print(f'  Register FAIL: {bin_name} - {e}')

    # 导出清单
    csv_path = mgr.export_csv(os.path.join(SAMPLES_DIR, '..', 'data', 'samples.csv'))
    print(f'\nSample list exported: {csv_path}')
    print(f'Total samples: {mgr.summary()["total_samples"]}')


if __name__ == '__main__':
    main()
