"""批量创建15个挑战性堆溢出样本 + 更新ground_truth.json"""

import json, os
from pathlib import Path

SAMPLE_DIR = Path(r"C:\Users\Administrator\Desktop\BinMind\deemo\tests\cve_samples\heap_overflow")

MAKEFILE_TEMPLATE = """CC=gcc
CFLAGS=-O2 -Wall -fno-stack-protector
TARGET={target}

all: $(TARGET).exe

$(TARGET).exe: $(TARGET).c
\t$(CC) $(CFLAGS) -o $@ $<

clean:
\trm -f $(TARGET).exe
"""

HEADER = """#include <stdio.h>
#include <stdlib.h>
#include <string.h>
"""

samples = {}

# cve_41: switch-case 写入路径安全 — 3个case, 每个写入都安全
# 检测器盲区: switch-case路径感知, case标签不影响guard提取
samples["cve_41_switch_path_safe"] = {
    "target": "switch_path_safe",
    "code": HEADER + """
/*
 * CVE-41: switch-case路径安全 — 每个case的写入都在边界内
 *
 * 模式: malloc(128); switch(mode) {
 *   case 0: memcpy(buf, src1, 32); break;
 *   case 1: memcpy(buf, src2, 64); break;
 *   default: memcpy(buf, src3, 96);
 * }
 * usable(128)=136, 最大写入96 <= 136 → SAFE
 */
int main() {
    int mode = 1;
    char *buf = (char *)malloc(128);
    if (!buf) return 1;

    char src1[64], src2[64], src3[128];
    memset(src1, 'A', 64);
    memset(src2, 'B', 64);
    memset(src3, 'C', 96);

    switch (mode) {
        case 0:
            memcpy(buf, src1, 32);
            break;
        case 1:
            memcpy(buf, src2, 64);
            break;
        default:
            memcpy(buf, src3, 96);
            break;
    }

    printf("switch_path_safe: mode=%d\\n", mode);
    free(buf);
    return 0;
}
""",
    "vuln": False,
}

# cve_42: switch-case 写入路径溢出 — 一个case溢出
samples["cve_42_switch_path_overflow"] = {
    "target": "switch_path_overflow",
    "code": HEADER + """
/*
 * CVE-42: switch-case路径溢出 — case 2写入超出边界
 *
 * 模式: malloc(64); switch(mode) {
 *   case 0: memcpy(buf, src1, 32); break;   // 32 <= usable(64)=72 → SAFE
 *   case 1: memcpy(buf, src2, 64); break;   // 64 <= 72 → SAFE
 *   case 2: memcpy(buf, src3, 128); break;  // 128 > 72 → OVERFLOW
 *   default: memcpy(buf, src4, 48); break;  // 48 <= 72 → SAFE
 * }
 */
int main() {
    int mode = 2;
    char *buf = (char *)malloc(64);
    if (!buf) return 1;

    char src1[64], src2[64], src3[128], src4[64];
    memset(src1, 'A', 64);
    memset(src2, 'B', 64);
    memset(src3, 'C', 128);
    memset(src4, 'D', 48);

    switch (mode) {
        case 0:
            memcpy(buf, src1, 32);
            break;
        case 1:
            memcpy(buf, src2, 64);
            break;
        case 2:
            memcpy(buf, src3, 128);
            break;
        default:
            memcpy(buf, src4, 48);
            break;
    }

    printf("switch_path_overflow: mode=%d\\n", mode);
    free(buf);
    return 0;
}
""",
    "vuln": True,
}

# cve_43: 指针别名链安全 — ptr→alias→buf, 写入安全
samples["cve_43_alias_chain_safe"] = {
    "target": "alias_chain_safe",
    "code": HEADER + """
/*
 * CVE-43: 指针别名链安全 — ptr→alias→buf, 多层别名
 *
 * 模式: buf = malloc(64); char *ptr = buf; char *alias = ptr;
 *       memcpy(alias, src, 56);  // 56 <= usable(64)=72 → SAFE
 * 别名追踪: alias→ptr→buf, 需要追踪两层别名链
 */
int main() {
    char *buf = (char *)malloc(64);
    if (!buf) return 1;

    char *ptr = buf;
    char *alias = ptr;

    char src[64];
    memset(src, 'X', 64);
    memcpy(alias, src, 56);

    printf("alias_chain_safe\\n");
    free(buf);
    return 0;
}
""",
    "vuln": False,
}

# cve_44: 指针别名链溢出 — ptr→alias→buf, 写入溢出
samples["cve_44_alias_chain_overflow"] = {
    "target": "alias_chain_overflow",
    "code": HEADER + """
/*
 * CVE-44: 指针别名链溢出 — ptr→alias→buf, 写入溢出
 *
 * 模式: buf = malloc(32); char *ptr = buf; char *alias = ptr;
 *       memcpy(alias, src, 128);  // 128 > usable(32)=40 → OVERFLOW
 */
int main() {
    char *buf = (char *)malloc(32);
    if (!buf) return 1;

    char *ptr = buf;
    char *alias = ptr;

    char src[128];
    memset(src, 'Y', 128);
    memcpy(alias, src, 128);

    printf("alias_chain_overflow\\n");
    free(buf);
    return 0;
}
""",
    "vuln": True,
}

# cve_45: cast别名安全 — void*→char*, 写入安全
samples["cve_45_cast_alias_safe"] = {
    "target": "cast_alias_safe",
    "code": HEADER + """
/*
 * CVE-45: cast别名安全 — void*中间变量+cast后写入
 *
 * 模式: void *raw = malloc(64); char *typed = (char*)raw;
 *       int *int_ptr = (int*)raw;
 *       memcpy(typed, src, 48);  // 48 <= usable(64)=72 → SAFE
 */
int main() {
    void *raw = malloc(64);
    if (!raw) return 1;

    char *typed = (char *)raw;
    int *int_ptr = (int *)raw;

    char src[64];
    memset(src, 'A', 64);
    memcpy(typed, src, 48);

    printf("cast_alias_safe\\n");
    free(raw);
    return 0;
}
""",
    "vuln": False,
}

# cve_46: cast别名溢出 — void*→char*, 写入溢出
samples["cve_46_cast_alias_overflow"] = {
    "target": "cast_alias_overflow",
    "code": HEADER + """
/*
 * CVE-46: cast别名溢出 — void*中间变量+cast后写入溢出
 *
 * 模式: void *raw = malloc(16); char *typed = (char*)raw;
 *       memcpy(typed, src, 64);  // 64 > usable(16)=24 → OVERFLOW
 */
int main() {
    void *raw = malloc(16);
    if (!raw) return 1;

    char *typed = (char *)raw;

    char src[64];
    memset(src, 'B', 64);
    memcpy(typed, src, 64);

    printf("cast_alias_overflow\\n");
    free(raw);
    return 0;
}
""",
    "vuln": True,
}

# cve_47: 条件分配安全 — 仅在条件满足时分配并写入
samples["cve_47_cond_alloc_safe"] = {
    "target": "cond_alloc_safe",
    "code": HEADER + """
/*
 * CVE-47: 条件分配安全 — guard约束下分配+写入
 *
 * 模式: if (n > 256) n = 256;
 *       buf = malloc(n);
 *       memcpy(buf, src, n);
 * guard: n<=256, memcpy(n) <= usable(256)=264 → SAFE
 */
int main(int argc, char **argv) {
    int n = 128;
    if (argc > 1) n = atoi(argv[1]);

    if (n > 256) n = 256;

    char *buf = (char *)malloc(n);
    if (!buf) return 1;

    char src[256];
    memset(src, 'D', 256);
    memcpy(buf, src, n);

    printf("cond_alloc_safe: n=%d\\n", n);
    free(buf);
    return 0;
}
""",
    "vuln": False,
}

# cve_48: 条件分配溢出 — guard不足, 写入溢出
samples["cve_48_cond_alloc_overflow"] = {
    "target": "cond_alloc_overflow",
    "code": HEADER + """
/*
 * CVE-48: 条件分配溢出 — guard不足以阻止溢出
 *
 * 模式: if (n > 256) n = 256;
 *       buf = malloc(n);
 *       memcpy(buf, src, 300);  // 300 > usable(256)=264 → OVERFLOW
 * guard约束n但写入大小固定300B, 超过n的最大值
 */
int main(int argc, char **argv) {
    int n = 128;
    if (argc > 1) n = atoi(argv[1]);

    if (n > 256) n = 256;

    char *buf = (char *)malloc(n);
    if (!buf) return 1;

    char src[512];
    memset(src, 'E', 512);
    memcpy(buf, src, 300);

    printf("cond_alloc_overflow: n=%d\\n", n);
    free(buf);
    return 0;
}
""",
    "vuln": True,
}

# cve_49: 复合算术偏移安全 — off=a*n+b, guard约束每项
samples["cve_49_compound_offset_safe"] = {
    "target": "compound_offset_safe",
    "code": HEADER + """
/*
 * CVE-49: 复合算术偏移安全 — offset由多变量算术构成
 *
 * 模式: malloc(256);
 *       if (base > 64) base = 64;
 *       if (stride > 4) stride = 4;
 *       if (extra > 32) extra = 32;
 *       off = base * stride + extra;  // max = 64*4+32 = 288
 *       memcpy(buf + off, src, 8);   // write_end = 288+8 = 296
 *       实际: off最大=64*4+32=288, write_end=296 > usable(256)=264 → 应溢出
 *       但需要精确分析复合算术 → 检测器可能因表达式复杂而INCONCLUSIVE
 * 重设: 让结果安全 → base最大16, stride最大4, extra最大32
 *       off = 16*4+32 = 96, write_end = 96+8 = 104 <= 264 → SAFE
 */
int main(int argc, char **argv) {
    int base = 8, stride = 2, extra = 16;
    if (argc > 1) base = atoi(argv[1]);
    if (argc > 2) stride = atoi(argv[2]);
    if (argc > 3) extra = atoi(argv[3]);

    if (base > 16) base = 16;
    if (stride > 4) stride = 4;
    if (extra > 32) extra = 32;

    char *buf = (char *)malloc(256);
    if (!buf) return 1;

    int off = base * stride + extra;
    char src[16];
    memset(src, 'F', 16);
    memcpy(buf + off, src, 8);

    printf("compound_offset_safe: off=%d\\n", off);
    free(buf);
    return 0;
}
""",
    "vuln": False,
}

# cve_50: 复合算术偏移溢出
samples["cve_50_compound_offset_overflow"] = {
    "target": "compound_offset_overflow",
    "code": HEADER + """
/*
 * CVE-50: 复合算术偏移溢出 — 复合表达式导致偏移超出缓冲区
 *
 * 模式: malloc(64);
 *       if (base > 32) base = 32;
 *       if (stride > 4) stride = 4;
 *       off = base * stride;  // max = 32*4 = 128
 *       memcpy(buf + off, src, 8);  // write_end = 128+8 = 136 > usable(64)=72 → OVERFLOW
 */
int main(int argc, char **argv) {
    int base = 16, stride = 2;
    if (argc > 1) base = atoi(argv[1]);
    if (argc > 2) stride = atoi(argv[2]);

    if (base > 32) base = 32;
    if (stride > 4) stride = 4;

    char *buf = (char *)malloc(64);
    if (!buf) return 1;

    int off = base * stride;
    char src[16];
    memset(src, 'G', 16);
    memcpy(buf + off, src, 8);

    printf("compound_offset_overflow: off=%d\\n", off);
    free(buf);
    return 0;
}
""",
    "vuln": True,
}

# cve_51: 结构体字段偏移安全
samples["cve_51_struct_field_offset_safe"] = {
    "target": "struct_field_offset_safe",
    "code": HEADER + """
/*
 * CVE-51: 结构体字段偏移安全 — 固定偏移+固定写入
 *
 * 模式:
 *   typedef struct { char a[32]; char b[32]; int len; } Header;
 *   buf = malloc(sizeof(Header));  // sizeof=68, usable=72
 *   memcpy(buf->b, src, 32);      // offset 32, write 32, end=64 <= 72 → SAFE
 *   buf->len = 42;                 // offset 64, write 4, end=68 <= 72 → SAFE
 */
typedef struct {
    char a[32];
    char b[32];
    int len;
} Header;

int main() {
    Header *buf = (Header *)malloc(sizeof(Header));
    if (!buf) return 1;

    char src[32];
    memset(src, 'H', 32);
    memcpy(buf->b, src, 32);
    buf->len = 42;

    printf("struct_field_offset_safe: len=%d\\n", buf->len);
    free(buf);
    return 0;
}
""",
    "vuln": False,
}

# cve_52: 结构体字段偏移溢出
samples["cve_52_struct_field_offset_overflow"] = {
    "target": "struct_field_offset_overflow",
    "code": HEADER + """
/*
 * CVE-52: 结构体字段偏移溢出 — 字段写入超出分配大小
 *
 * 模式:
 *   typedef struct { char a[32]; char b[32]; } SmallHeader;  // sizeof=64
 *   buf = malloc(32);  // 分配过小
 *   memcpy(buf->b, src, 32);  // offset 32, write 32, end=64 > usable(32)=40 → OVERFLOW
 */
typedef struct {
    char a[32];
    char b[32];
} SmallHeader;

int main() {
    SmallHeader *buf = (SmallHeader *)malloc(32);
    if (!buf) return 1;

    char src[32];
    memset(src, 'I', 32);
    memcpy(buf->b, src, 32);

    printf("struct_field_offset_overflow\\n");
    free(buf);
    return 0;
}
""",
    "vuln": True,
}

# cve_53: 工厂函数+跨函数guard安全
samples["cve_53_factory_cross_guard_safe"] = {
    "target": "factory_cross_guard_safe",
    "code": HEADER + """
/*
 * CVE-53: 工厂函数+跨函数guard安全
 *
 * 模式:
 *   char *make_buf(int sz) { if (sz > 128) sz = 128; return malloc(sz); }
 *   void fill_buf(char *b, int n) { if (n > 64) n = 64; memcpy(b, data, n); }
 *   main: int n = 200; buf = make_buf(n); fill_buf(buf, n);
 *   guard: sz<=128, n<=64, write_end=64 <= usable(128)=136 → SAFE
 */
char *make_buf(int sz) {
    if (sz > 128) sz = 128;
    return (char *)malloc(sz);
}

void fill_buf(char *b, int n) {
    if (n > 64) n = 64;
    char data[64];
    memset(data, 'J', 64);
    memcpy(b, data, n);
}

int main(int argc, char **argv) {
    int n = 200;
    if (argc > 1) n = atoi(argv[1]);

    char *buf = make_buf(n);
    if (!buf) return 1;
    fill_buf(buf, n);

    printf("factory_cross_guard_safe: n=%d\\n", n);
    free(buf);
    return 0;
}
""",
    "vuln": False,
}

# cve_54: 工厂函数+跨函数写入溢出
samples["cve_54_factory_cross_write_overflow"] = {
    "target": "factory_cross_write_overflow",
    "code": HEADER + """
/*
 * CVE-54: 工厂函数+跨函数写入溢出
 *
 * 模式:
 *   char *make_buf(int sz) { return malloc(sz); }
 *   void fill_buf(char *b, int n) { memcpy(b, data, n); }
 *   main: int n = 200; buf = make_buf(32); fill_buf(buf, n);
 *   alloc=32 usable=40, write=200 > 40 → OVERFLOW
 */
char *make_buf(int sz) {
    return (char *)malloc(sz);
}

void fill_buf(char *b, int n) {
    char data[256];
    memset(data, 'K', 256);
    memcpy(b, data, n);
}

int main(int argc, char **argv) {
    int n = 200;
    if (argc > 1) n = atoi(argv[1]);

    char *buf = make_buf(32);
    if (!buf) return 1;
    fill_buf(buf, n);

    printf("factory_cross_write_overflow: n=%d\\n", n);
    free(buf);
    return 0;
}
""",
    "vuln": True,
}

# cve_55: 返回指针后溢出 — 工厂函数返回子指针
samples["cve_55_returned_ptr_overflow"] = {
    "target": "returned_ptr_overflow",
    "code": HEADER + """
/*
 * CVE-55: 返回子指针后溢出
 *
 * 模式:
 *   char *get_field_buf() { return (char*)malloc(16); }
 *   main: char *p = get_field_buf(); memcpy(p, src, 128);
 *   alloc=16 usable=24, write=128 > 24 → OVERFLOW
 * 检测器需要: 识别get_field_buf是工厂函数, 返回malloc结果
 */
char *get_field_buf() {
    return (char *)malloc(16);
}

int main() {
    char *p = get_field_buf();
    if (!p) return 1;

    char src[128];
    memset(src, 'Z', 128);
    memcpy(p, src, 128);

    printf("returned_ptr_overflow\\n");
    free(p);
    return 0;
}
""",
    "vuln": True,
}

# 写入所有样本
gt_entries = {}
for name, spec in samples.items():
    d = SAMPLE_DIR / name
    d.mkdir(exist_ok=True)

    # 写 .c 文件
    c_path = d / f"{spec['target']}.c"
    c_path.write_text(spec["code"], encoding="utf-8")

    # 写 Makefile
    mf_path = d / "Makefile"
    mf_path.write_text(MAKEFILE_TEMPLATE.format(target=spec["target"]), encoding="utf-8")

    # ground truth entry
    vuln = spec["vuln"]
    gt_entries[name] = {
        "cve": f"CVE-2024-{41 + list(samples.keys()).index(name):04d} analog",
        "pattern": spec.get("pattern", ""),
        "expected_vuln": vuln,
        "expected_type": "heap_overflow" if vuln else "safe",
        "notes": f"{'Overflow' if vuln else 'Safe'}: {spec['target']}"
    }
    print(f"Created {name} ({'VULN' if vuln else 'SAFE'})")

# 更新 ground_truth.json
gt_path = SAMPLE_DIR / "ground_truth.json"
with open(gt_path, encoding="utf-8") as f:
    gt = json.load(f)

for name, entry in gt_entries.items():
    gt["samples"][name] = entry

gt["summary"]["total"] = len(gt["samples"])
gt["summary"]["vulnerable"] = sum(1 for s in gt["samples"].values() if s["expected_vuln"])
gt["summary"]["safe"] = sum(1 for s in gt["samples"].values() if not s["expected_vuln"])
gt["summary"]["safe_samples"] = [
    name for name, s in gt["samples"].items() if not s["expected_vuln"]
]

with open(gt_path, "w", encoding="utf-8") as f:
    json.dump(gt, f, indent=2, ensure_ascii=False)

print(f"\nTotal samples: {gt['summary']['total']}")
print(f"Vulnerable: {gt['summary']['vulnerable']}")
print(f"Safe: {gt['summary']['safe']}")
print(f"Ground truth updated: {gt_path}")
