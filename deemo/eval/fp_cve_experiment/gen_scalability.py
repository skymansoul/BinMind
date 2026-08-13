"""PCFV 可扩展性样本生成器 — 合成大二进制测量管线时间/内存复杂度.

创建: 2023-08-21
设计决策:
  - 合成源码 = n 组 malloc+memcpy+free 模式 (真实堆操作形态),
    规模 100/500/1000/2000/4000 组, 对应约 2K~80K 条指令.
  - 每组 memcpy 大小与分配大小匹配 (安全), 避免大量告警干扰
    耗时测量 (耗时主导项是指令解析与值流追踪).
  - 编译 -O0: 保留全部 malloc/memcpy 调用点.
"""
import argparse
import glob
import os
import subprocess

from _common import HERE as _HERE
OUT = os.path.join(_HERE, 'scalability')
CC = os.environ.get('CC', 'gcc')

SCALES = (100, 500, 1000, 2000, 4000)


def gen_source(n: int) -> str:
    lines = [
        '#include <stdio.h>',
        '#include <stdlib.h>',
        '#include <string.h>',
        '',
        'int main(int argc, char **argv) {',
        '    (void)argc; (void)argv;',
        '    volatile int sink = 0;',
    ]
    for i in range(n):
        sz = 64 + (i * 7) % 256
        lines.append('    char *buf_%d = (char *)malloc(%d);' % (i, sz))
        lines.append('    if (!buf_%d) return -1;' % i)
        lines.append('    memcpy(buf_%d, "payload", 8);' % i)
        lines.append('    sink += buf_%d[0];' % i)
        lines.append('    free(buf_%d);' % i)
    lines.append('    printf("%d\\n", sink);')
    lines.append('    return 0;')
    lines.append('}')
    return '\n'.join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', default=OUT)
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    for n in SCALES:
        src = os.path.join(args.out, 'scal_%d.c' % n)
        exe = os.path.join(args.out, 'scal_%d.exe' % n)
        with open(src, 'w', encoding='utf-8') as f:
            f.write(gen_source(n))
        proc = subprocess.run(
            [CC, '-O0', '-g', '-fno-stack-protector', src, '-o', exe],
            capture_output=True, text=True, timeout=180)
        if proc.returncode != 0:
            print('  COMPILE FAIL', n, proc.stderr[:150])
            continue
        print('scal_%d: %d groups' % (n, n))
    print('scalability samples ready:', args.out)


if __name__ == '__main__':
    main()
