"""批量生成17个堆溢出测试样本 (源码+Makefile+README).

每个样本是独立的 C 程序, 编译为 ELF 后可供扫描器测试.
"""

import os

BASE = os.path.dirname(os.path.abspath(__file__))

SAMPLES = {
    "cve_2021_3156_sudo": {
        "desc": "sudoedit heap overflow — size mismatch between alloc and copy",
        "code": r"""/* CVE-2021-3156 — sudoedit heap overflow (size mismatch) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static char *set_cmnd(const char *src, size_t raw_size) {
    size_t safe_size = (raw_size > 255) ? 255 : raw_size;
    char *buf = (char *)malloc(safe_size + 1);
    if (!buf) return NULL;
    memcpy(buf, src, raw_size);  /* BUG: uses raw_size, not safe_size */
    buf[raw_size] = '\0';
    return buf;
}
int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <input>\n", argv[0]); return 1; }
    char *r = set_cmnd(argv[1], strlen(argv[1]));
    if (r) { printf("[*] %s\n", r); free(r); }
    return 0;
}
""",
    },
    "cve_2019_13142_mongoose": {
        "desc": "Mongoose OS HTTP parser — off-by-one in name_len allocation",
        "code": r"""/* CVE-2019-13142 — Mongoose OS Content-Disposition heap overflow */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int parse_name(const char *header, char **out) {
    const char *s = strstr(header, "name=\"");
    if (!s) return -1;
    s += 6;
    const char *e = strchr(s, '"');
    if (!e) return -1;
    size_t len = (size_t)(e - s);
    *out = (char *)malloc(len);  /* BUG: should be len+1 */
    if (!*out) return -1;
    memcpy(*out, s, len);
    (*out)[len] = '\0';  /* writes one byte past allocation */
    return 0;
}
int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <header>\n", argv[0]); return 1; }
    char *name = NULL;
    if (parse_name(argv[1], &name) == 0) { printf("[*] %s\n", name); free(name); }
    return 0;
}
""",
    },
    "cve_off_by_one_malloc_001": {
        "desc": "malloc(n) with off-by-one null write at buf[n]",
        "code": r"""/* malloc(n) → write n+1 bytes (off-by-one) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static char *copy_str(const char *src, size_t len) {
    char *buf = (char *)malloc(len);
    if (!buf) return NULL;
    memcpy(buf, src, len);
    buf[len] = '\0';  /* BUG: writes beyond len */
    return buf;
}
int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <str>\n", argv[0]); return 1; }
    char *r = copy_str(argv[1], strlen(argv[1]));
    if (r) { printf("[*] %s\n", r); free(r); }
    return 0;
}
""",
    },
    "cve_size_mismatch_memcpy_002": {
        "desc": "malloc(fixed) + memcpy with external size — size mismatch",
        "code": r"""/* Alloc fixed size, copy variable size => overflow when size > alloc */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define FIXED_BUF 1024
int main(int argc, char **argv) {
    unsigned char *buf = (unsigned char *)malloc(FIXED_BUF);
    if (!buf) return 1;
    size_t len = argc > 1 ? strlen(argv[1]) : 0;
    memcpy(buf, argv[1], len);  /* BUG: len can exceed FIXED_BUF */
    printf("[*] copied %zu bytes\n", len);
    free(buf);
    return 0;
}
""",
    },
    "cve_unbounded_strcpy_003": {
        "desc": "strcpy into heap buffer — no bounds check",
        "code": r"""/* Unbounded strcpy into heap buffer */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    char *buf = (char *)malloc(64);
    if (!buf) return 1;
    if (argc > 1) strcpy(buf, argv[1]);  /* BUG: no length check */
    printf("[*] %s\n", buf);
    free(buf);
    return 0;
}
""",
    },
    "cve_integer_overflow_alloc_004": {
        "desc": "Multiplication overflow in nmemb*size → wrap to tiny allocation",
        "code": r"""/* nmemb*size overflow => allocate few bytes, write many */
#include <stdio.h>
#include <stdlib.h>
static void *alloc_array(size_t n, size_t sz) {
    return malloc(n * sz);  /* BUG: no overflow check */
}
int main(void) {
    size_t n = 0x40000001;
    int *arr = (int *)alloc_array(n, sizeof(int));
    if (!arr) return 1;
    for (size_t i = 0; i < 100; i++) arr[i] = (int)i;  /* BUG: overflow */
    printf("[*] arr[99]=%d\n", arr[99]);
    free(arr);
    return 0;
}
""",
    },
    "cve_nested_alloc_confusion_005": {
        "desc": "Nested allocation with confused size — inner loop exceeds alloc",
        "code": r"""/* Nested malloc: outer alloc based on len, inner loop uses more */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct record { size_t n; char **fields; };
static struct record *parse(const char *s) {
    struct record *r = (struct record *)malloc(sizeof(*r));
    if (!r) return NULL;
    size_t len = strlen(s);
    r->fields = (char **)malloc(len * sizeof(char *));
    r->n = len / 4 + 1;  /* BUG: n > len on small inputs */
    for (size_t i = 0; i < r->n; i++)
        r->fields[i] = strdup(s);
    return r;
}
int main(int argc, char **argv) {
    struct record *r = parse(argc > 1 ? argv[1] : "test");
    if (r) {
        for (size_t i = 0; i < r->n; i++) free(r->fields[i]);
        free(r->fields); free(r);
    }
    return 0;
}
""",
    },
    "cve_loop_bound_error_006": {
        "desc": "Loop bound error — write ints into char array",
        "code": r"""/* Alloc n bytes, write n ints (4x the allocation) */
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    size_t n = argc > 1 ? (size_t)atoi(argv[1]) : 8;
    char *buf = (char *)malloc(n);
    if (!buf) return 1;
    int *ip = (int *)buf;
    for (size_t i = 0; i < n; i++) ip[i] = (int)i;  /* BUG: writes n*4 bytes */
    printf("[*] last=%d\n", ip[n-1]);
    free(buf);
    return 0;
}
""",
    },
    "cve_signed_unsigned_mismatch_007": {
        "desc": "Signed/unsigned mismatch — negative size bypasses bounds check",
        "code": r"""/* Signed→unsigned conversion => negative becomes huge */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int process(const char *data, int signed_len) {
    if (signed_len <= 0) return -1;
    if (signed_len > 4096) return -1;
    size_t len = (size_t)signed_len;
    char *buf = (char *)malloc(len);
    if (!buf) return -1;
    memcpy(buf, data, len);
    free(buf);
    return 0;
}
int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 16;
    process("testdata", n);
    return 0;
}
""",
    },
    "cve_tlv_length_override_008": {
        "desc": "TLV parser — declared length < actual data length",
        "code": r"""/* TLV: allocate per declared_len, copy actual_len > declared_len */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct tlv { unsigned short type, length; unsigned char value[]; };
int main(int argc, char **argv) {
    unsigned short dlen = argc > 1 ? (unsigned short)atoi(argv[1]) : 10;
    const char *actual = "AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDDEEEEEEEEFFFFFFFFFF";
    size_t alen = strlen(actual);
    struct tlv *p = (struct tlv *)malloc(sizeof(*p) + dlen);
    if (!p) return 1;
    p->type = 1; p->length = dlen;
    memcpy(p->value, actual, alen);  /* BUG: alen > dlen */
    printf("[*] type=%u dlen=%u alen=%zu\n", p->type, p->length, alen);
    free(p);
    return 0;
}
""",
    },
    "cve_chunk_metadata_corrupt_009": {
        "desc": "Overflow into adjacent chunk metadata (unsafe unlink vector)",
        "code": r"""/* Overflow into next chunk's metadata */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    char *a = (char *)malloc(128);
    char *b = (char *)malloc(128);
    char *c = (char *)malloc(128);
    if (!a || !b || !c) return 1;
    memset(a, 'A', 128); memset(b, 'B', 128); memset(c, 'C', 128);
    size_t off = argc > 1 ? (size_t)atoi(argv[1]) : 200;
    if (off < 512) a[off] = 'X';  /* BUG: overflows into b */
    printf("[*] a=%p b=%p c=%p off=%zu\n", (void*)a, (void*)b, (void*)c, off);
    free(a); free(b); free(c);
    return 0;
}
""",
    },
    "cve_calloc_type_confusion_010": {
        "desc": "calloc array then memset with wrong element size",
        "code": r"""/* calloc(n, 4) then memset(n, 0, n*8) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 100;
    int *arr = (int *)calloc(n, sizeof(int));
    if (!arr) return 1;
    memset(arr, 0, n * sizeof(long));  /* BUG: memset more than allocated */
    printf("[*] arr[0]=%d alloc=%zu memset=%zu\n",
           arr[0], n*sizeof(int), n*sizeof(long));
    free(arr);
    return 0;
}
""",
    },
    "cve_realloc_use_old_size_011": {
        "desc": "realloc shrinks buffer, but subsequent memmove uses old size",
        "code": r"""/* realloc to smaller size, then memmove with old larger size */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    size_t old_sz = 256, new_sz = argc > 1 ? (size_t)atoi(argv[1]) : 64;
    char *buf = (char *)malloc(old_sz);
    if (!buf) return 1;
    memset(buf, 'A', old_sz);
    buf = (char *)realloc(buf, new_sz);
    memmove(buf + 10, buf, old_sz - 10);  /* BUG: old_sz > new_sz */
    printf("[*] buf[0]='%c'\n", buf[0]);
    free(buf);
    return 0;
}
""",
    },
    "cve_format_string_heap_012": {
        "desc": "User-controlled format string via heap buffer",
        "code": r"""/* Format string vuln via heap-allocated buffer */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    char *fmt = (char *)malloc(256);
    if (!fmt) return 1;
    if (argc > 1) strncpy(fmt, argv[1], 255);
    fmt[255] = '\0';
    printf(fmt);  /* BUG: format string vuln */
    printf("\n");
    free(fmt);
    return 0;
}
""",
    },
    "cve_use_after_free_013": {
        "desc": "UAF — dangling pointer to freed heap object reused",
        "code": r"""/* Use-after-free: free then use dangling pointer */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct node { int id; char data[64]; struct node *next; } node_t;
int main(void) {
    node_t *n1 = (node_t *)malloc(sizeof(node_t));
    if (!n1) return 1;
    n1->id = 1; strcpy(n1->data, "original");
    free(n1);
    char *str = (char *)malloc(32);
    if (!str) return 1;
    strcpy(str, "OVERWRITTEN!");
    node_t *d = n1;  /* BUG: dangling pointer */
    printf("[*] id=%d data=%s\n", d->id, d->data);
    free(str);
    return 0;
}
""",
    },
    "cve_alignment_aware_014": {
        "desc": "Alignment-aware access at chunk boundary — unaligned access leaks",
        "code": r"""/* Access beyond aligned chunk boundary */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    char *a = (char *)malloc(32);
    char *b = (char *)malloc(32);
    if (!a || !b) return 1;
    memset(a, 'A', 32); memset(b, 'B', 32);
    size_t o = argc > 1 ? (size_t)atoi(argv[1]) : 40;
    printf("[*] a[%zu]='%c'\n", o, a[o]);  /* BUG: reads beyond a */
    a[o] = 'X';
    printf("[*] b[0]='%c'\n", b[0]);
    free(a); free(b);
    return 0;
}
""",
    },
    "cve_double_free_015": {
        "desc": "Double-free — same pointer freed twice",
        "code": r"""/* Double-free vulnerability */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *buf = (char *)malloc(128);
    if (!buf) return 1;
    strcpy(buf, "test data");
    free(buf);
    /* ... many lines of code ... */
    free(buf);  /* BUG: double free */
    printf("[*] done\n");
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

    makefile = f"""CC = gcc
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

- **漏洞类型**: 堆缓冲区溢出 (CWE-122)
- **描述**: {info['desc']}
- **触发条件**: 参数控制分配大小或拷贝长度
- **预期检测**: 静态分析应标记为潜在堆溢出
"""
    with open(os.path.join(d, "README.md"), "w") as f:
        f.write(readme)


if __name__ == "__main__":
    for name, info in SAMPLES.items():
        write_sample(name, info)
        print(f"  [OK] {name}")
    print(f"Generated {len(SAMPLES)} test samples in {BASE}")
