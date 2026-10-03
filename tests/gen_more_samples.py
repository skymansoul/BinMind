"""补充 int_overflow 剩余7个样本 + format_string 剩余5个样本。"""
import os

IO_BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'samples', 'int_overflow')
FMT_BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'samples', 'format_string')
MK = 'CC=gcc\nCFLAGS=-g -O0 -fno-stack-protector\n\nall: vuln\n\nvuln: vuln.c\n\t$(CC) $(CFLAGS) -o vuln vuln.c\n\nclean:\n\trm -f vuln\n'

IO_MORE = {
'io_narrow_cast': (r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* IO-09: size_t被窄化为int — 在32位平台可能截断 */
int main(int argc, char **argv) {
    size_t real_size = 0x100000001ULL;
    int narrow = (int)(real_size & 0xFFFFFFFF);
    char *buf = (char *)malloc((size_t)narrow);
    if (!buf) return 1;
    memset(buf, 0, real_size);  /* VULNERABLE */
    free(buf); return 0;
}
''', '**CWE-681** — Incorrect Conversion between Numeric Types'),
'io_alloc_size': (r'''#include <stdio.h>
#include <stdlib.h>
/* IO-10: malloc(0) — 当size计算溢出为0时, malloc(0)返回有效指针 */
int main(int argc, char **argv) {
    unsigned short n = (unsigned short)(argc > 1 ? atoi(argv[1]) : 65536);
    /* 65536 % 65536 = 0 → n=0 → malloc(0) */
    size_t alloc = (size_t)n * 1024;  /* 0 * 1024 = 0 */
    char *buf = (char *)malloc(alloc);
    printf("malloc(%zu) = %p\n", alloc, (void *)buf);
    if (buf) {
        for (int i = 0; i < 100; i++) buf[i] = 'X';  /* VULNERABLE */
        free(buf);
    }
    return 0;
}
''', '**CWE-190** — Integer Overflow leading to malloc(0)'),
'io_array_index': (r'''#include <stdio.h>
#include <stdlib.h>
/* IO-11: 数组索引由溢出的整数计算 — 负索引访问 */
int main(int argc, char **argv) {
    int idx = argc > 1 ? atoi(argv[1]) : -1;
    int buf[256];
    for (int i = 0; i < 256; i++) buf[i] = i;
    /* idx=-1 → buf[-1]=0 可能破坏栈 */
    unsigned int uidx = (unsigned int)idx;
    if (uidx < 256) buf[idx] = 0;  /* VULNERABLE: idx是负的但uidx检查通过 */
    printf("buf[0]=%d\n", buf[0]);
    return 0;
}
''', '**CWE-129** — Improper Validation of Array Index'),
'io_length_field': (r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* IO-12: 协议长度字段溢出 — 从网络/文件读取的长度字段可能恶意构造 */
int main(int argc, char **argv) {
    unsigned short net_len = (unsigned short)(argc > 1 ? atoi(argv[1]) : 0xFFFF);
    size_t actual = (size_t)net_len + 16;  /* net_len=0xFFFF → 0x1000F → 无溢出 */
    /* 但如果net_len来自网络字节序 htons(0xFFFF)=0xFFFF, 计算可能安全 */
    char *buf = (char *)malloc(actual);
    if (!buf) return 1;
    memset(buf, 0, actual);
    size_t copy = (size_t)net_len * 2;  /* VULNERABLE: 0xFFFF*2=0x1FFFE, 但product已溢出ushort */
    memcpy(buf, "data", copy < actual ? copy : actual);
    free(buf); return 0;
}
''', '**CWE-190** — Integer Overflow in Protocol Length'),
'io_crypto_nonce': (r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* IO-13: 加密nonce/计数器溢出 — 常用于流密码/CTR模式 */
int main(void) {
    unsigned int nonce = 0xFFFFFFF0u;
    char chunks[16][16];
    memset(chunks, 0, sizeof(chunks));
    for (unsigned int i = 0; i < 32; i++) {
        unsigned int ctr = nonce + i;  /* VULNERABLE: nonce+32回绕 */
        /* ctr循环使用, 同一nonce加密两个不同明文 — 密码学灾难 */
        if (ctr < 16) sprintf(chunks[ctr], "block_%u", ctr);
    }
    printf("chunk[0]=%s\n", chunks[0]);
    return 0;
}
''', '**CWE-190** — Integer Overflow in Cryptographic Counter'),
'io_parse_len': (r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* IO-14: 解析器中的长度字段 — ntohl/反序列化后的宽度问题 */
int main(int argc, char **argv) {
    /* 模拟 ntohl(*(uint32_t*)pkt) */
    unsigned long pkt_len = (unsigned long)(argc > 1 ? atol(argv[1]) : 0xFFFFFFFF);
    /* 检查不充分: 只检查上界 */
    if (pkt_len > 65536) { printf("too large\n"); return 1; }
    /* pkt_len=0 → malloc(1) 但后续按60处理 */
    size_t alloc = pkt_len ? (size_t)pkt_len : 1;
    char *buf = (char *)malloc(alloc);
    if (!buf) return 1;
    memset(buf, 0, 60);  /* VULNERABLE if alloc < 60 */
    free(buf); return 0;
}
''', '**CWE-190** — Implicit Integer Overflow in Parser'),
'io_mixed_types': (r'''#include <stdio.h>
#include <stdlib.h>
/* IO-15: 混合类型算术 — int*unsigned long 的隐式提升歧义 */
int main(int argc, char **argv) {
    int count = argc > 1 ? atoi(argv[1]) : 1000000;
    unsigned long elem_size = 4096;
    /* count*siz → int*ulong → ulong, 但count先被提升 */
    unsigned long total = (unsigned long)count * elem_size;
    if (total > 100 * 1024 * 1024) { printf("too large\n"); return 1; }
    int *buf = (int *)malloc((size_t)total);
    if (!buf) { printf("alloc failed\n"); return 1; }
    for (int i = 0; i < count; i++) buf[i] = i;  /* VULNERABLE if total too small */
    free(buf); return 0;
}
''', '**CWE-681** — Mixed-type Arithmetic Overflow'),
}

FMT_MORE = {
'fmt_double_percent': (r'''#include <stdio.h>
/* FMT-11: %% 转义 — 不应误报双百分号 */
int main(int argc, char **argv) {
    printf("%%s %%n %%d\n");  /* SAFE: 全部转义 */
    return 0;
}
''', '**SAFE** — Double-percent escape, should NOT report'),
'fmt_nested_call': (r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* FMT-12: 嵌套调用 — 格式串经过多层函数传递 */
void inner(const char *s) { printf(s); }  /* 可能危险 */
void outer(const char *input) { inner(input); }  /* 透传 */

int main(int argc, char **argv) {
    if (argc > 1) outer(argv[1]);  /* VULNERABLE: 用户输入到printf */
    else outer("safe: %d\n");
    return 0;
}
''', '**CWE-134** — Format string via nested call chain'),
'fmt_loop_write': (r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* FMT-13: 循环中构造格式串并通过%n写入 */
int main(int argc, char **argv) {
    int vals[10] = {0};
    char fmt[256] = {0};
    if (argc > 1) {
        for (int i = 0; i < 10; i++)
            sprintf(fmt + strlen(fmt), "%%%d$n", i+1);
        printf(fmt, &vals[0],&vals[1],&vals[2],&vals[3],&vals[4],
               &vals[5],&vals[6],&vals[7],&vals[8],&vals[9]);
    }
    printf("vals[0]=%d\n", vals[0]);
    return 0;
}
''', '**CWE-134** — Format string constructed in loop'),
'fmt_inline_const': (r'''#include <stdio.h>
/* FMT-14: 内联常量 — fprintf(stderr, "const") 是安全的 */
int main(void) {
    fprintf(stdout, "constant format string\n");  /* SAFE */
    fprintf(stdout, "value: %d\n", 42);  /* SAFE */
    return 0;
}
''', '**SAFE** — Inline constant format, should NOT report'),
'fmt_external_input': (r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* FMT-15: 外部输入直接传给sprintf作为格式串 */
int main(int argc, char **argv) {
    char buf[512];
    if (argc > 1)
        sprintf(buf, argv[1], 42);  /* VULNERABLE: argv[1]作为格式串 */
    else
        sprintf(buf, "answer=%d", 42);
    printf("%s\n", buf);
    return 0;
}
''', '**CWE-134** — sprintf with external format string'),
}

for name, (code, desc) in IO_MORE.items():
    d = os.path.join(IO_BASE, name); os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, 'vuln.c'), 'w') as f: f.write(code)
    with open(os.path.join(d, 'Makefile'), 'w') as f: f.write(MK)
    with open(os.path.join(d, 'README.md'), 'w') as f:
        f.write(f'# {name}\n{desc}\n\n## Detection Goal\nBinMind int_overflow detector verification.\n')
    print(f'  IO: {name}')

for name, (code, desc) in FMT_MORE.items():
    d = os.path.join(FMT_BASE, name); os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, 'vuln.c'), 'w') as f: f.write(code)
    with open(os.path.join(d, 'Makefile'), 'w') as f: f.write(MK)
    with open(os.path.join(d, 'README.md'), 'w') as f:
        f.write(f'# {name}\n{desc}\n\n## Detection Goal\nBinMind FSCS format constraint verification.\n')
    print(f'  FMT: {name}')

print('Done supplementing samples')
