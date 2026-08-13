"""生成15个整数溢出测试样本。"""
import os

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'samples', 'int_overflow')

SAMPLES = {
'io_mul_overflow': r'''#include <stdio.h>
#include <stdlib.h>
/* IO-01: 乘法整数溢出导致堆分配不足 */
int main(int argc, char **argv) {
    int count = argc > 1 ? atoi(argv[1]) : 1000;
    /* size_t alloc = count * sizeof(int);  若count=0x40000001, 乘积溢出 */
    size_t n = (size_t)count * sizeof(int);
    int *buf = (int *)malloc(n);
    if (!buf) { printf("malloc failed\n"); return 1; }
    for (int i = 0; i < count; i++) buf[i] = i;  /* VULNERABLE if count overflowed */
    printf("last=%d\n", buf[count-1]);
    free(buf); return 0;
}
''',
'io_add_wrap': r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* IO-02: 加法回绕 — offset+size可能超过UINT_MAX */
int main(int argc, char **argv) {
    unsigned int offset = argc > 1 ? (unsigned)atoi(argv[1]) : 0xFFFF0000u;
    unsigned int size   = 4096;
    if (offset + size < offset) {  /* 显式检查了但代码仍可能走else */
        printf("wrap detected\n"); return 1;
    }
    char *buf = (char *)malloc(offset + size);  /* VULNERABLE: 如果offset很大 */
    if (!buf) return 1;
    memset(buf + offset, 0, size);
    free(buf); return 0;
}
''',
'io_sign_mismatch': r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* IO-03: 有符号/无符号比较错误 — 负数被隐式转换为大正数 */
int main(int argc, char **argv) {
    int user_len = argc > 1 ? atoi(argv[1]) : -1;
    /* user_len是int, 但sizeof返回size_t(无符号), 负数被提升为大正数 */
    if ((unsigned)user_len > 1024) { printf("too large\n"); return 1; }
    /* user_len=-1 → (unsigned)-1=0xFFFFFFFF > 1024, 但检查的是"too large" */
    char *buf = (char *)malloc(1024);
    if (!buf) return 1;
    if (user_len > 0) memcpy(buf, "data", (size_t)user_len);  /* VULNERABLE */
    free(buf); return 0;
}
''',
'io_truncation': r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* IO-04: 类型截断 — uint64被截断为uint32导致分配不足 */
int main(int argc, char **argv) {
    unsigned long long total = 0x100000001ULL;  /* > 2^32 */
    unsigned int truncated = (unsigned int)total;  /* 截断为1 */
    char *buf = (char *)malloc(truncated);
    if (!buf) return 1;
    memset(buf, 'A', (size_t)total);  /* VULNERABLE: 超出分配 */
    free(buf); return 0;
}
''',
'io_shift_wrap': r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* IO-05: 左移溢出 — 1 << bits 可能超过类型范围 */
int main(int argc, char **argv) {
    int bits = argc > 1 ? atoi(argv[1]) : 30;
    size_t alloc = (size_t)1 << bits;  /* bits=31时, 1<<31溢出int, 提升后可能异常 */
    char *buf = (char *)malloc(alloc);
    if (!buf) { printf("malloc failed for 1<<%d\n", bits); return 1; }
    memset(buf, 0, alloc);
    printf("allocated 1<<%d = %zu bytes\n", bits, alloc);
    free(buf); return 0;
}
''',
'io_loop_counter': r'''#include <stdio.h>
#include <stdlib.h>
/* IO-06: 循环计数器溢出 — 小类型计数器回绕导致无限循环/越界 */
int main(void) {
    unsigned short i;  /* 最大65535 */
    int *buf = (int *)malloc(70000 * sizeof(int));
    if (!buf) return 1;
    for (i = 0; i < 70000; i++)  /* i永远<70000, 因为ushort最大65535 */
        buf[i] = (int)i;  /* VULNERABLE: 无限循环 + 越界 */
    free(buf); return 0;
}
''',
'io_size_calc': r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* IO-07: 复杂尺寸计算中的隐式溢出 — (a+b)*c 可能溢出 */
int main(int argc, char **argv) {
    int hdr = 64;
    int body = argc > 1 ? atoi(argv[1]) : 2000000000;
    int footer = 64;
    /* size = hdr + body * 2 + footer  中间乘法可能溢出 */
    size_t size = (size_t)(hdr + body * 2 + footer);
    char *buf = (char *)malloc(size);
    if (!buf) { printf("alloc failed\n"); return 1; }
    memset(buf, 0, size);
    free(buf); return 0;
}
''',
'io_offset_wrap': r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* IO-08: 偏移计算回绕 — ptr+offset可能回绕到低地址 */
int main(int argc, char **argv) {
    unsigned int base = 0xFFFFFF00u;
    unsigned int off  = argc > 1 ? (unsigned)atoi(argv[1]) : 512u;
    char *buf = (char *)malloc(4096);
    if (!buf) return 1;
    memset(buf, 0, 4096);
    /* base+off可能超过UINT_MAX回绕 */
    unsigned int idx = base + off;
    if (idx < 4096) buf[idx] = 'X';  /* VULNERABLE: idx可能回绕 */
    printf("idx=%u\n", idx);
    free(buf); return 0;
}
''',
}

MAKEFILE = 'CC=gcc\nCFLAGS=-g -O0 -fno-stack-protector\n\nall: vuln\n\nvuln: vuln.c\n\t$ $(CFLAGS) -o vuln vuln.c\n\nclean:\n\trm -f vuln\n'

for name, code in SAMPLES.items():
    d = os.path.join(BASE, name)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, 'vuln.c'), 'w') as f: f.write(code)
    with open(os.path.join(d, 'Makefile'), 'w') as f: f.write(MAKEFILE)
    with open(os.path.join(d, 'README.md'), 'w') as f:
        f.write(f'# {name}\n**CWE-190** — Integer Overflow leading to Heap Overflow\n\n')
        f.write(f'## Detection Goal\nBinMind int_overflow_detector + allocator_model should ')
        f.write(f'detect the integer overflow that leads to undersized allocation.\n')
    print(f'  OK: {name}')

print(f'Done: {len(SAMPLES)} int_overflow samples')
