"""批量生成16个良性堆操作样本 (源码+Makefile+README).

用途: 误报率基准 — 每个样本均为安全代码, 但形态上触发既有检测器
的典型误报根源:
  - 空间最近邻分配匹配 (多分配错配)
  - 未知写入大小一律报告
  - 未知偏移循环写一律报告
  - strcpy 无界复制保守报告

样本命名 tn_NN_*; ground truth 见 ../../sample_labels.json.
"""

import os

BASE = os.path.dirname(os.path.abspath(__file__))

SAMPLES = {
    "tn_01_memcpy_exact": {
        "desc": "malloc(256) + memcpy(dst, src, 256) — 精确匹配",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    unsigned char *buf = (unsigned char *)malloc(256);
    if (!buf) return 1;
    unsigned char src[256];
    memset(src, 1, sizeof(src));
    memcpy(buf, src, 256);   /* 大小精确等于分配 */
    printf("[*] %d\n", buf[0]);
    free(buf);
    return 0;
}
""",
    },
    "tn_02_guarded_memcpy": {
        "desc": "if (len <= 256) memcpy — 守卫经寄存器链传递",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    unsigned char *buf = (unsigned char *)malloc(256);
    if (!buf) return 1;
    size_t len = argc > 1 ? strlen(argv[1]) : 16;
    size_t ok = len;                 /* 守卫变量经赋值链 */
    if (ok <= 256) {
        memcpy(buf, argv[1], ok);    /* 守卫保证不越界 */
        printf("[*] %zu\n", ok);
    }
    free(buf);
    return 0;
}
""",
    },
    "tn_03_loop_bounded": {
        "desc": "malloc(100*4) + for(i<100) 写4字节 — 循环界匹配",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
int main(void) {
    int *arr = (int *)malloc(100 * sizeof(int));
    if (!arr) return 1;
    for (int i = 0; i < 100; i++) arr[i] = i;   /* 恰为分配范围 */
    printf("[*] %d\n", arr[99]);
    free(arr);
    return 0;
}
""",
    },
    "tn_04_nested_loop_bounded": {
        "desc": "嵌套循环乘积不超分配",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
int main(void) {
    int *m = (int *)malloc(50 * 50 * sizeof(int));
    if (!m) return 1;
    for (int i = 0; i < 50; i++)
        for (int j = 0; j < 50; j++)
            m[i * 50 + j] = i + j;   /* 内层界已知 */
    printf("[*] %d\n", m[0]);
    free(m);
    return 0;
}
""",
    },
    "tn_05_strcpy_literal": {
        "desc": "malloc(64) + strcpy(buf, 短字面量) — rodata 长度可证",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *buf = (char *)malloc(64);
    if (!buf) return 1;
    strcpy(buf, "literal short");    /* 长度 14 <= 64 */
    printf("[*] %s\n", buf);
    free(buf);
    return 0;
}
""",
    },
    "tn_06_multialloc_provenance": {
        "desc": "p1=malloc(16), p2=malloc(256), memcpy(p2,src,128) — 最近邻匹配陷阱",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p1 = (char *)malloc(16);
    char *p2 = (char *)malloc(256);
    if (!p1 || !p2) return 1;
    memcpy(p2, "0123456789abcdef0123456789abcdef", 32);  /* 目标是 p2, 128>=32 */
    printf("[*] %s %s\n", p1, p2);
    free(p1); free(p2);
    return 0;
}
""",
    },
    "tn_07_stack_src_copy": {
        "desc": "栈源 → 堆目标精确 memcpy",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    char stack_src[128];
    memset(stack_src, 'S', sizeof(stack_src));
    char *buf = (char *)malloc(128);
    if (!buf) return 1;
    memcpy(buf, stack_src, 128);     /* 大小匹配 */
    printf("[*] %c\n", buf[0]);
    free(buf);
    return 0;
}
""",
    },
    "tn_08_struct_fields": {
        "desc": "结构体字段写入均在对象内",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct rec { int id; char name[48]; double score; };
int main(void) {
    struct rec *r = (struct rec *)malloc(sizeof(struct rec));
    if (!r) return 1;
    r->id = 7;
    strcpy(r->name, "alice");        /* 48字节字段内 */
    r->score = 3.5;
    printf("[*] %s\n", r->name);
    free(r);
    return 0;
}
""",
    },
    "tn_09_field_offset_write": {
        "desc": "已知偏移写入, 偏移+宽度 ≤ 可用大小",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct hdr { unsigned len; unsigned flags; unsigned char body[0x100]; };
int main(void) {
    struct hdr *h = (struct hdr *)malloc(sizeof(struct hdr));
    if (!h) return 1;
    h->len = 0x80;
    h->flags = 0;
    memset(h->body, 0, 0x80);         /* 偏移 8, 写入 0x80, 总量在对象内 */
    printf("[*] len=%u\n", h->len);
    free(h);
    return 0;
}
""",
    },
    "tn_10_strncpy_checked": {
        "desc": "strncpy(dst, src, N-1) N=分配大小",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    char *buf = (char *)malloc(256);
    if (!buf) return 1;
    strncpy(buf, argc > 1 ? argv[1] : "hello", 255);  /* 显式上界 */
    buf[255] = '\0';
    printf("[*] %s\n", buf);
    free(buf);
    return 0;
}
""",
    },
    "tn_11_memmove_inplace": {
        "desc": "memmove 同一缓冲区内位移",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *buf = (char *)malloc(128);
    if (!buf) return 1;
    memset(buf, 'X', 128);
    memmove(buf + 8, buf, 64);       /* 均在 128 内 */
    printf("[*] %c\n", buf[8]);
    free(buf);
    return 0;
}
""",
    },
    "tn_12_realloc_grow": {
        "desc": "realloc 扩容后按新大小写",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *buf = (char *)malloc(32);
    if (!buf) return 1;
    char *nb = (char *)realloc(buf, 512);
    if (!nb) { free(buf); return 1; }
    memset(nb, 'R', 512);            /* 新大小 512 内 */
    printf("[*] %c\n", nb[511]);
    free(nb);
    return 0;
}
""",
    },
    "tn_13_memset_exact": {
        "desc": "memset(buf, 0, alloc) — 精确",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    int *arr = (int *)malloc(64 * sizeof(int));
    if (!arr) return 1;
    memset(arr, 0, 64 * sizeof(int));
    printf("[*] %d\n", arr[0]);
    free(arr);
    return 0;
}
""",
    },
    "tn_14_snprintf_bounded": {
        "desc": "snprintf(dst, alloc, ...) — 上界即分配大小",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    char *buf = (char *)malloc(256);
    if (!buf) return 1;
    int n = snprintf(buf, 256, "value=%d", argc);  /* 上界 256 */
    printf("[*] %d\n", n);
    free(buf);
    return 0;
}
""",
    },
    "tn_15_free_no_reuse": {
        "desc": "free 后无复用 (UAF 对照阴性)",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
int main(void) {
    char *buf = (char *)malloc(128);
    if (!buf) return 1;
    printf("[*] %d\n", buf[0]);
    free(buf);                       /* 之后不再使用 */
    return 0;
}
""",
    },
    "tn_16_printf_literal_fmt": {
        "desc": "printf 字面量格式串 (格式化字符串阴性对照)",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    char *buf = (char *)malloc(64);
    if (!buf) return 1;
    snprintf(buf, 64, "%d", argc);
    printf("value=%s\n", buf);       /* 格式串为字面量 */
    free(buf);
    return 0;
}
""",
    },
}


def write_sample(name, info):
    d = os.path.join(BASE, name)
    os.makedirs(os.path.join(d, "src"), exist_ok=True)
    with open(os.path.join(d, "src", "vuln.c"), "w") as f:
        f.write(info["code"])
    makefile = """CC = gcc
CFLAGS = -Wall -O0 -g -no-pie -fno-stack-protector -z execstack
TARGET = vuln

all: $(TARGET)

$(TARGET): src/vuln.c
\t$(CC) $(CFLAGS) -o $@ $<

clean:
\trm -f $(TARGET)

run: $(TARGET)
\t./$(TARGET)

.PHONY: all clean run
"""
    with open(os.path.join(d, "Makefile"), "w") as f:
        f.write(makefile)
    readme = f"""# {name}

- **类型**: 良性样本 (安全代码)
- **描述**: {info['desc']}
- **设计意图**: 该形态触发既有检测器的典型误报根源, 用于量化
  误报率基线 (baseline) 与 PG-WBV 抑制管线的差异
- **预期检测**: 不应标记任何堆溢出
"""
    with open(os.path.join(d, "README.md"), "w") as f:
        f.write(readme)


if __name__ == "__main__":
    for name, info in SAMPLES.items():
        write_sample(name, info)
        print(f"  [OK] {name}")
    print(f"Generated {len(SAMPLES)} benign samples in {BASE}")
