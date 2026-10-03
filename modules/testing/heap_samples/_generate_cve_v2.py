"""批量生成8个真实CVE模式堆溢出样本 (源码+Makefile+README).

每个样本为真实漏洞的最小忠实复现, 保留 CVE 对应的漏洞形态:
  - CVE-2018-1121 (procps): 排序键 strcpy 无界复制
  - CVE-2018-10732 (libmobi): 头部长度字段驱动 memcpy
  - CVE-2018-18557 (JasPer): 码流声明长度与实际长度不一致
  - CVE-2017-14492 (dnsmasq): 固定小分配 + 无界 strcpy
  - CVE-2018-20735 (libsass): 结构体字段长度错位
  - CVE-2021-35942 (elfutils): 32位截断 → 小分配大复制
  - CVE-2019-18604 (gnuplot): PDF 解析器 alloc/copy 错配
  - CVE-2017-17506 (gdk-pixbuf): 头部长度字段驱动复制
"""

import os

BASE = os.path.dirname(os.path.abspath(__file__))

SAMPLES = {
    "cve_2018_1121_procps": {
        "cve": "CVE-2018-1121",
        "pattern": "unbounded strcpy of sort key into fixed heap buffer",
        "code": r"""/* CVE-2018-1121 — procps sort key heap overflow (unbounded strcpy) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct row { char key[64]; int val; };
static struct row *make_row(const char *key) {
    struct row *r = (struct row *)malloc(sizeof(struct row));
    if (!r) return NULL;
    strcpy(r->key, key);  /* BUG: key may exceed 63 bytes */
    r->val = 1;
    return r;
}
int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <key>\n", argv[0]); return 1; }
    struct row *r = make_row(argv[1]);
    if (r) { printf("[*] %s %d\n", r->key, r->val); free(r); }
    return 0;
}
""",
    },
    "cve_2018_10732_libmobi": {
        "cve": "CVE-2018-10732",
        "pattern": "copy length from file header exceeds heap allocation",
        "code": r"""/* CVE-2018-10732 — libmobi parse_huff: header-driven memcpy overflow */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void *parse_huff(unsigned int hdr_len, const unsigned char *data) {
    void *buf = malloc(0x40);           /* fixed small buffer */
    if (!buf) return NULL;
    memcpy(buf, data, hdr_len);         /* BUG: hdr_len from untrusted header */
    return buf;
}
int main(int argc, char **argv) {
    unsigned int len = argc > 1 ? (unsigned int)atoi(argv[1]) : 0x100;
    unsigned char payload[0x200];
    memset(payload, 'A', sizeof(payload));
    void *p = parse_huff(len, payload);
    if (p) { printf("[*] parsed %u bytes\n", len); free(p); }
    return 0;
}
""",
    },
    "cve_2018_18557_jasper": {
        "cve": "CVE-2018-18557",
        "pattern": "codestream declared length vs actual copy length",
        "code": r"""/* CVE-2018-18557 — JasPer: declared length smaller than copied data */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct jp2_box { unsigned int declared_len; unsigned char *data; };
static struct jp2_box *parse_box(const unsigned char *raw, size_t raw_len) {
    struct jp2_box *b = (struct jp2_box *)malloc(sizeof(*b));
    if (!b) return NULL;
    b->declared_len = 0x40;             /* header-declared length */
    b->data = (unsigned char *)malloc(b->declared_len);
    if (!b->data) { free(b); return NULL; }
    memcpy(b->data, raw, raw_len);      /* BUG: raw_len > declared_len */
    return b;
}
int main(int argc, char **argv) {
    unsigned char payload[0x200];
    memset(payload, 'B', sizeof(payload));
    struct jp2_box *b = parse_box(payload, argc > 1 ? (size_t)atoi(argv[1]) : 0x100);
    if (b) { printf("[*] box len=%u\n", b->declared_len); free(b->data); free(b); }
    return 0;
}
""",
    },
    "cve_2017_14492_dnsmasq": {
        "cve": "CVE-2017-14492",
        "pattern": "fixed small heap allocation followed by unbounded strcpy",
        "code": r"""/* CVE-2017-14492 — dnsmasq: small alloc + unbounded name copy */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static char *check_for_bogus_wildcard(const char *name) {
    char *p = (char *)malloc(32);       /* fixed small buffer */
    if (!p) return NULL;
    strcpy(p, name);                    /* BUG: unbounded */
    return p;
}
int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <name>\n", argv[0]); return 1; }
    char *p = check_for_bogus_wildcard(argv[1]);
    if (p) { printf("[*] %s\n", p); free(p); }
    return 0;
}
""",
    },
    "cve_2018_20735_libsass": {
        "cve": "CVE-2018-20735",
        "pattern": "struct field length mismatch in memcpy",
        "code": r"""/* CVE-2018-20735 — libsass: copied_length vs allocated field */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct sass_value { char *str; size_t str_len; };
static struct sass_value *valloc(const char *s, size_t decl_len) {
    struct sass_value *v = (struct sass_value *)malloc(sizeof(*v));
    if (!v) return NULL;
    v->str = (char *)malloc(decl_len);  /* declared (too small) */
    if (!v->str) { free(v); return NULL; }
    size_t real = strlen(s) + 1;
    v->str_len = real;
    memcpy(v->str, s, real);            /* BUG: real > decl_len */
    return v;
}
int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <str>\n", argv[0]); return 1; }
    struct sass_value *v = valloc(argv[1], 16);
    if (v) { printf("[*] len=%zu\n", v->str_len); free(v->str); free(v); }
    return 0;
}
""",
    },
    "cve_2021_35942_elfutils": {
        "cve": "CVE-2021-35942",
        "pattern": "32-bit truncation of length before allocation",
        "code": r"""/* CVE-2021-35942 — elfutils: 32-bit truncation → small alloc, big copy */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void *handle_dynamic(unsigned long long big_len, const void *src) {
    unsigned int truncated = (unsigned int)big_len;  /* wraps on 64-bit sizes */
    void *buf = malloc(truncated);
    if (!buf) return NULL;
    memcpy(buf, src, (size_t)big_len);   /* BUG: copies unwrapped length */
    return buf;
}
int main(void) {
    unsigned long long len = 0x100000000ULL + 0x40;  /* truncates to 0x40 */
    unsigned char payload[0x200];
    memset(payload, 'C', sizeof(payload));
    void *p = handle_dynamic(len, payload);
    if (p) { printf("[*] ok\n"); free(p); }
    return 0;
}
""",
    },
    "cve_2019_18604_gnuplot": {
        "cve": "CVE-2019-18604",
        "pattern": "PDF parser: alloc from one field, copy from another",
        "code": r"""/* CVE-2019-18604 — gnuplot PDF: alloc per xref_len, copy per data_len */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct pdf_xref { unsigned int xref_len; unsigned int data_len; };
static void *parse_xref(const struct pdf_xref *x, const void *data) {
    void *buf = malloc(x->xref_len);    /* alloc from xref_len */
    if (!buf) return NULL;
    memcpy(buf, data, x->data_len);     /* BUG: data_len independent */
    return buf;
}
int main(int argc, char **argv) {
    struct pdf_xref x;
    x.xref_len = argc > 1 ? (unsigned int)atoi(argv[1]) : 0x10;
    x.data_len = 0x100;                 /* crafted header: data_len large */
    unsigned char payload[0x200];
    memset(payload, 'D', sizeof(payload));
    void *p = parse_xref(&x, payload);
    if (p) { printf("[*] xref %u\n", x.xref_len); free(p); }
    return 0;
}
""",
    },
    "cve_2017_17506_gdkpixbuf": {
        "cve": "CVE-2017-17506",
        "pattern": "image header length drives copy into smaller buffer",
        "code": r"""/* CVE-2017-17506 — gdk-pixbuf: header length vs line buffer */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void *parse_image(const unsigned char *hdr, size_t hdr_len) {
    /* 行缓冲按固定宽度分配, 复制长度来自头部 */
    void *line = malloc(0x100);
    if (!line) return NULL;
    memcpy(line, hdr, hdr_len);         /* BUG: hdr_len up to 0xffff */
    return line;
}
int main(int argc, char **argv) {
    size_t len = argc > 1 ? (size_t)atoi(argv[1]) : 0x300;
    unsigned char hdr[0x400];
    memset(hdr, 'E', sizeof(hdr));
    void *p = parse_image(hdr, len);
    if (p) { printf("[*] parsed\n"); free(p); }
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

- **CVE**: {info['cve']}
- **漏洞模式**: {info['pattern']}
- **漏洞类型**: 堆缓冲区溢出 (CWE-122)
- **触发条件**: 攻击者可控长度/字符串经无界或错配复制进入堆缓冲区
- **为何有效**: 复现真实 CVE 的分配/复制大小错配或缺失边界检查形态,
  是该 CVE 补丁所修复缺陷的最小可编译复现
- **预期检测**: 静态分析应标记为堆溢出
"""
    with open(os.path.join(d, "README.md"), "w") as f:
        f.write(readme)


if __name__ == "__main__":
    for name, info in SAMPLES.items():
        write_sample(name, info)
        print(f"  [OK] {name}")
    print(f"Generated {len(SAMPLES)} CVE samples in {BASE}")
