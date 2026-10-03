"""SysV ABI 变体生成器 — 为堆溢出语料库编译 SysV 调用约定变体.

设计决策:
  - MinGW 的 -mabi=sysv 在 PE 目标上生成 SysV 调用约定代码
    (参数走 rdi/rsi/rdx/rcx), 用于验证双 ABI 支持.
  - 输出 vuln_sysv.c 副本 + vuln_sysv.exe, 与原始样本共存.
"""
import argparse
import glob
import os
import shutil
import subprocess

from _common import HERE as _HERE
CC = os.environ.get('CC', 'gcc')


def gen_one(sample_dir: str) -> bool:
    src_path = os.path.join(sample_dir, 'vuln.c')
    sysv_c = os.path.join(sample_dir, 'vuln_sysv.c')
    sysv_exe = os.path.join(sample_dir, 'vuln_sysv.exe')
    if not os.path.exists(sysv_c):
        shutil.copyfile(src_path, sysv_c)
    proc = subprocess.run(
        [CC, '-O0', '-mabi=sysv', '-g', '-fno-stack-protector', sysv_c,
         '-o', sysv_exe],
        capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        print('  SYSV FAIL', sample_dir, proc.stderr[:160])
        return False
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--corpus', default=os.path.join(_HERE, 'corpus'))
    args = ap.parse_args()
    n = 0
    for d in sorted(glob.glob(os.path.join(args.corpus, '*'))):
        if not os.path.isdir(d) or not os.path.exists(
                os.path.join(d, 'vuln.c')):
            continue
        if gen_one(d):
            n += 1
        print('sysv:', os.path.basename(d))
    print('sysv variants: %d' % n)


if __name__ == '__main__':
    main()
