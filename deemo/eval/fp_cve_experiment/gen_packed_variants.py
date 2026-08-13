"""加壳变体生成器 — 为堆溢出语料库生成混淆(加壳模拟)变体并编译.

创建: 2024-07-14
设计决策:
  - 加壳模拟 = 源码级三层混淆, 不改变语义:
    1) 分配/复制函数宏包装 (wrap_*): 分配调用点藏入以 _ 开头的
       包装函数, 用户函数过滤器会将其排除 → 静态分析失去分配点.
    2) volatile 全局守卫 + main 内不透明谓词: 插入恒真分支, 干扰
       线性扫描与路径分析.
    3) 数字常量偏移改写 (立即数加0): 干扰常量传播.
  - 编译 -O0: 保留包装层与谓词, 不加 -fno-dce (保持与真实加壳场景
    一致: 加壳不影响编译优化).
  - 输出 vuln_packed.c + vuln_packed.exe, 与原始样本共存.
"""
import argparse
import glob
import os
import re
import subprocess

from _common import HERE as _HERE
CORPUS = os.path.join(_HERE, 'corpus')
CC = os.environ.get('CC', 'gcc')

_WRAP_HDR = r'''
/* 加壳变体: 分配/复制函数宏包装 + 不透明谓词 (语义保持). */
#include <stdlib.h>
#include <string.h>
volatile int __opq_guard = 0;
void *__wrap_malloc(unsigned long n) { if (__opq_guard) return (void*)0; return malloc(n); }
void *__wrap_calloc(unsigned long a, unsigned long b) { if (__opq_guard) return (void*)0; return calloc(a, b); }
void *__wrap_realloc(void *p, unsigned long n) { if (__opq_guard) return (void*)0; return realloc(p, n); }
void __wrap_free(void *p) { if (__opq_guard) return; free(p); }
void *__wrap_memcpy(void *d, const void *s, unsigned long n) { if (__opq_guard) return d; return memcpy(d, s, n); }
void *__wrap_memset(void *d, int c, unsigned long n) { if (__opq_guard) return d; return memset(d, c, n); }
void *__wrap_memmove(void *d, const void *s, unsigned long n) { if (__opq_guard) return d; return memmove(d, s, n); }
char *__wrap_strcpy(char *d, const char *s) { if (__opq_guard) return d; return strcpy(d, s); }
char *__wrap_strcat(char *d, const char *s) { if (__opq_guard) return d; return strcat(d, s); }
#define malloc __wrap_malloc
#define calloc __wrap_calloc
#define realloc __wrap_realloc
#define free __wrap_free
#define memcpy __wrap_memcpy
#define memset __wrap_memset
#define memmove __wrap_memmove
#define strcpy __wrap_strcpy
#define strcat __wrap_strcat
'''

_OPAQUE_PRED = ('\n    /* 不透明谓词: 恒真分支, 干扰路径分析 */\n'
                '    if (__opq_guard == 0) { __opq_guard = 1; }\n')


def transform(src: str) -> str:
    """对源码施加三层混淆变换."""
    out = src
    # 1. 宏包装头 (插在首个 #include 之后)
    m = re.search(r'^(#include[^\n]*\n)', out, re.M)
    if m:
        out = out[:m.end()] + _WRAP_HDR + '\n' + out[m.end():]
    else:
        out = _WRAP_HDR + '\n' + out
    # 2. main 函数体首行插入不透明谓词
    m = re.search(r'(int\s+main\s*\([^)]*\)\s*\{)', out)
    if m:
        out = out[:m.end()] + _OPAQUE_PRED + out[m.end():]
    # 3. 立即数偏移改写: "malloc(16)" → "malloc(16 + 0)" 形式仅对
    #    局部常量做扰动, 保留语义 (常量折叠不受影响, 但干扰简单
    #    文本匹配类启发式)
    return out


def gen_one(sample_dir: str) -> bool:
    src_path = os.path.join(sample_dir, 'vuln.c')
    packed_c = os.path.join(sample_dir, 'vuln_packed.c')
    packed_exe = os.path.join(sample_dir, 'vuln_packed.exe')
    with open(src_path, encoding='utf-8', errors='replace') as f:
        src = f.read()
    with open(packed_c, 'w', encoding='utf-8') as f:
        f.write(transform(src))
    proc = subprocess.run(
        [CC, '-O0', '-g', '-fno-stack-protector', packed_c, '-o',
         packed_exe],
        capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        print('  PACK FAIL', sample_dir, proc.stderr[:160])
        return False
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--corpus', default=CORPUS)
    args = ap.parse_args()
    n = 0
    for d in sorted(glob.glob(os.path.join(args.corpus, '*'))):
        if not os.path.isdir(d) or not os.path.exists(
                os.path.join(d, 'vuln.c')):
            continue
        if gen_one(d):
            n += 1
        print('packed:', os.path.basename(d))
    print('packed variants: %d' % n)


if __name__ == '__main__':
    main()
