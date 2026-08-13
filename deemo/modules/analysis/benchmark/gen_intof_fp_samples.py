"""批量生成整数溢出对抗样本 (8 误报诱发 + 8 真实漏洞).

设计依据: 针对 binary_int_overflow_scanner (I-GUARD) 的误报根源 —
  R-I1: imul/shl 一律标记, 无操作数数值性分析 (常量缩放/掩码约束)
  R-I3: 不区分 32/64 位乘法与移位量 (imul eax vs imul rax, shl 2 vs 63)
  R-I4: 无"溢出后写入验证" (欠分配但无大写入不是可利用漏洞)

每个 fp_NN 对应一个同形态真漏洞 vuln_NN, 用于验证改进在
消除误报时不损失召回.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _sample_writer import write_sample

BASE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(BASE, "samples_intof_fp")

SAMPLES = {
    # 误报诱发 (安全)
    "fp_01_mask_constrained_mul": {
        "kind": "safe",
        "desc": "乘法前 AND 掩码约束 — 乘积上界可静态确定",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    unsigned n = argc > 1 ? (unsigned)atoi(argv[1]) : 16;
    n &= 0xFFF;                        /* 掩码约束: n <= 4095 */
    char *buf = (char *)malloc(n * 4); /* 乘积 <= 16380, 无溢出 */
    if (!buf) return 1;
    memset(buf, 0, n * 4);
    free(buf);
    return 0;
}
""",
    },
    "fp_02_32bit_mul_widen": {
        "kind": "safe",
        "desc": "掩码约束后 32 位乘法 — 乘积上界可静态确定",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    unsigned a = argc > 1 ? (unsigned)atoi(argv[1]) : 1000;
    a &= 0xFFF;                        /* 掩码: a <= 4095 */
    unsigned b = 8;
    char *buf = (char *)malloc((size_t)a * b);  /* <= 32760 */
    if (!buf) return 1;
    memset(buf, 0, (size_t)a * b);
    free(buf);
    return 0;
}
""",
    },
    "fp_03_struct_scale": {
        "kind": "safe",
        "desc": "掩码约束的结构体缩放 (imul r, r, 0x30) — 乘积有界",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct rec { int id; char name[32]; double score; };  /* 48 字节 */
int main(int argc, char **argv) {
    unsigned n = argc > 1 ? (unsigned)atoi(argv[1]) : 10;
    n &= 0xFFFF;                       /* 掩码: n <= 65535 */
    struct rec *arr = (struct rec *)malloc(n * sizeof(struct rec));
    if (!arr) return 1;
    for (unsigned i = 0; i < n; i++) {
        arr[i].id = (int)i;
        arr[i].score = 1.0;
    }
    free(arr);
    return 0;
}
""",
    },
    "fp_04_proper_checked_mul": {
        "kind": "safe",
        "desc": "乘法后正确溢出检查 (上界合理)",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    unsigned n = argc > 1 ? (unsigned)atoi(argv[1]) : 16;
    size_t sz = (size_t)n * sizeof(int);
    if (sz > 0x100000) return 1;       /* 正确检查 */
    int *arr = (int *)malloc(sz);
    if (!arr) return 1;
    memset(arr, 0, sz);
    free(arr);
    return 0;
}
""",
    },
    "fp_05_small_shift": {
        "kind": "safe",
        "desc": "小移位 (shl 2) — 可静态证明安全",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    unsigned n = argc > 1 ? (unsigned)atoi(argv[1]) : 64;
    n &= 0xFFFF;                       /* n <= 65535 */
    char *buf = (char *)malloc(n << 2);/* 乘积 <= 262140 */
    if (!buf) return 1;
    memset(buf, 0, (size_t)n << 2);
    free(buf);
    return 0;
}
""",
    },
    "fp_06_no_large_write": {
        "kind": "safe",
        "desc": "欠分配风险存在但后续写入量受控 — 不可利用",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    unsigned n = argc > 1 ? (unsigned)atoi(argv[1]) : 100000;
    char *buf = (char *)malloc(n * 4); /* n=100000 → 400000 正常 */
    if (!buf) return 1;
    buf[0] = 'X';                      /* 固定小写入 */
    buf[1] = '\0';
    printf("[*] %s\n", buf);
    free(buf);
    return 0;
}
""",
    },
    "fp_07_shift_by_small_const": {
        "kind": "safe",
        "desc": "常量左移一位 (字符串复制场景)",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    size_t len = argc > 1 ? strlen(argv[1]) : 8;
    char *buf = (char *)malloc(len + 1);  /* len+1, 无乘法 */
    if (!buf) return 1;
    strcpy(buf, argc > 1 ? argv[1] : "hello");
    printf("[*] %s\n", buf);
    free(buf);
    return 0;
}
""",
    },
    "fp_08_short_index_mul": {
        "kind": "safe",
        "desc": "短整型索引放大 (常量元素大小)",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    unsigned short idx = argc > 1 ? (unsigned short)atoi(argv[1]) : 100;
    char *buf = (char *)malloc((size_t)idx * 16);
    if (!buf) return 1;
    memset(buf, 0, (size_t)idx * 16);
    free(buf);
    return 0;
}
""",
    },
    # 真实漏洞 (对照)
    "vuln_01_mul_overflow_alloc": {
        "kind": "vuln",
        "desc": "n*4 乘法溢出 → 小分配 → 循环写越界 (CWE-680)",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    unsigned n = argc > 1 ? (unsigned)atoi(argv[1]) : 0x40000000;
    int *arr = (int *)malloc(n * sizeof(int));  /* 溢出回绕 */
    if (!arr) return 1;
    for (unsigned i = 0; i < 100; i++) arr[i] = (int)i;  /* 越界写 */
    printf("[*] %d\n", arr[99]);
    free(arr);
    return 0;
}
""",
    },
    "vuln_02_shl_overflow_alloc": {
        "kind": "vuln",
        "desc": "左移 20 位溢出 → 小分配 → 大数据写入",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    unsigned n = argc > 1 ? (unsigned)atoi(argv[1]) : 0x1000;
    char *buf = (char *)malloc(n << 20);  /* n<<20 溢出 */
    if (!buf) return 1;
    memset(buf, 'A', 0x100000);           /* 远超实际分配 */
    free(buf);
    return 0;
}
""",
    },
    "vuln_03_32bit_wrap_alloc": {
        "kind": "vuln",
        "desc": "32 位乘法回绕 → 小分配 → 数组写",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    unsigned n = argc > 1 ? (unsigned)atoi(argv[1]) : 0x100000;
    int *arr = (int *)malloc((size_t)(n * 8));  /* 32 位回绕 */
    if (!arr) return 1;
    for (unsigned i = 0; i < 1000; i++) arr[i] = (int)i;
    printf("[*] %d\n", arr[999]);
    free(arr);
    return 0;
}
""",
    },
    "vuln_04_checked_wrong_bound": {
        "kind": "vuln",
        "desc": "检查上界远大于实际域 — 检查无效",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    unsigned n = argc > 1 ? (unsigned)atoi(argv[1]) : 0x10000000;
    size_t sz = (size_t)n * 4;
    if (sz > 0x100000000ULL) return 1;  /* 上界 4G, 无效检查 */
    char *buf = (char *)malloc(sz);
    if (!buf) return 1;
    memset(buf, 0, 0x1000);             /* 写入超分配 */
    free(buf);
    return 0;
}
""",
    },
    "vuln_05_checked_wrong_reg": {
        "kind": "vuln",
        "desc": "检查的是无关寄存器 — 乘积未校验",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    unsigned n = argc > 1 ? (unsigned)atoi(argv[1]) : 0x40000000;
    unsigned flag = argc;
    size_t sz = (size_t)n * 4;
    if (flag == 0) return 1;            /* 检查 flag, 非 sz */
    char *buf = (char *)malloc(sz);
    if (!buf) return 1;
    memset(buf, 0, 0x1000);
    free(buf);
    return 0;
}
""",
    },
    "vuln_06_calloc_nmemb": {
        "kind": "vuln",
        "desc": "调用点乘法后 calloc — nmemb 溢出",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    unsigned n = argc > 1 ? (unsigned)atoi(argv[1]) : 0x20000000;
    char *buf = (char *)calloc(n * 4, 16);  /* 调用点乘法溢出 */
    if (!buf) return 1;
    for (unsigned i = 0; i < 100; i++) buf[i] = (char)i;
    free(buf);
    return 0;
}
""",
    },
    "vuln_07_cross_func_mul": {
        "kind": "vuln",
        "desc": "包装函数返回乘法结果 → malloc 欠分配",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static size_t calc_size(unsigned n) {
    return (size_t)(n * 4);             /* 32 位乘法溢出 */
}
int main(int argc, char **argv) {
    unsigned n = argc > 1 ? (unsigned)atoi(argv[1]) : 0x40000000;
    char *buf = (char *)malloc(calc_size(n));
    if (!buf) return 1;
    memset(buf, 0, 0x1000);
    free(buf);
    return 0;
}
""",
    },
    "vuln_08_add_chain_wrap": {
        "kind": "vuln",
        "desc": "加法链回绕 → 小分配 → 越界写",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    unsigned n = argc > 1 ? (unsigned)atoi(argv[1]) : 0x7FFFFFFF;
    unsigned sz = n + n;                /* 加法回绕为 0xFFFFFFFE */
    char *buf = (char *)malloc(sz);
    if (!buf) return 1;
    memset(buf, 0, 0x1000);
    free(buf);
    return 0;
}
""",
    },
}




if __name__ == "__main__":
    for name, info in SAMPLES.items():
        write_sample(name, info, OUT)
        print(f"  [OK] {name}")
    print(f"Generated {len(SAMPLES)} intof samples in {OUT}")
