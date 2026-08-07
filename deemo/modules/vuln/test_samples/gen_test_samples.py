"""生成堆溢出测试样本集的批处理脚本.

创建: 2026-06-05
用途: 一次性生成 ≥16 个 CVE 风格堆溢出测试样本,
      每个含 C 源码 + Makefile + README.

覆盖的溢出模式:
  1. 直接溢出 (malloc 固定大小, 写入越界)
  2. int→heap 传递
  3. 守卫不充分 (有边界检查但条件错误)
  4. 跨函数溢出 (caller alloc, callee 越界写入)
  5. 循环累积溢出 (memcpy in loop, 累积 > alloc)
  6. sprintf 无界写入
  7. memcpy 计算 size (运行时 size > alloc)
  8. 对齐填充假阳性 (写入在对齐填充内, 应为 safe)
  9. strncpy 截断溢出 (截断导致后续写入越界)
  10. realloc 缩小后溢出
  11. calloc 溢出 (nmemb*size 回绕)
  12. 条件溢出 (仅特定分支溢出)
  13. 多分配指针混淆 (写错 malloc 缓冲区)
  14. 嵌套结构偏移 (深层 struct 成员越界)
  15. 守卫充分安全 (有正确边界检查, 应判 safe)
  16. 精确边界写入 (offset+size == alloc, 应判 safe)
  17. 大偏移小写入
  18. 16位整数溢出→堆溢出 (uint16_t size 翻转)

运行: python gen_test_samples.py [output_dir]
"""
import os, sys

SAMPLES = [
    {
        'id': 'sample01_direct_overflow',
        'title': 'CVE-2024-0001 Direct Heap Overflow',
        'pattern': 'malloc(64) → write at offset 96 (越界32字节)',
        'expected': 'TP (true positive)',
        'trigger': '偏移96 > alloc(64)usable=64 → 明确越界',
        'code': r'''/* Direct heap overflow — 简单越界写入.
 *
 * CVE pattern: malloc(64), write at offset 96.
 * 这是最基础的堆溢出形式, 任何检测器都应检出.
 * Expected: TP (confidence ≥ 0.90)
 */
#include <stdlib.h>
#include <string.h>

int main() {
    char *buf = (char *)malloc(64);
    if (!buf) return 1;
    memset(buf, 'A', 96);  /* OVERFLOW: 写入96字节, alloc仅64 */
    buf[0] = '\0';
    free(buf);
    return 0;
}
''',
    },
    {
        'id': 'sample02_int_overflow_to_heap',
        'title': 'CVE-2016-2208 Style Integer Overflow → Heap Overflow',
        'pattern': 'imul size → malloc(wrapped_size) → memcpy(original_size)',
        'expected': 'TP (true positive)',
        'trigger': '乘法回绕: n*sizeof(struct) < n → malloc 不足 → 写入越界',
        'code': r'''/* Integer overflow → heap overflow.
 *
 * n * sizeof(elem) 回绕到小值, malloc 分配不足,
 * memcpy 按原始 n 写入 → 堆溢出.
 * Expected: TP (confidence ≥ 0.85)
 */
#include <stdlib.h>
#include <string.h>

typedef struct { char data[256]; } Elem;

int main() {
    unsigned int n = 0x01000001;  /* 16M+1, 乘积回绕 */
    size_t alloc_size = n * sizeof(Elem);
    /* alloc_size = 0x01000001 * 256 mod 2^32 = 256, 远小于 n*256 */
    char *buf = (char *)malloc(alloc_size);
    if (!buf) return 1;
    /* memcpy 期望写 n*sizeof(Elem) ≈ 256MB, 实际 alloc=256B → 溢出 */
    memset(buf, 0, (size_t)n * 256);
    free(buf);
    return 0;
}
''',
    },
    {
        'id': 'sample03_insufficient_guard',
        'title': 'CVE-2024-0003 Insufficient Bounds Check',
        'pattern': 'cmp + jbe 守卫存在但条件偏弱 (off-by-one)',
        'expected': 'TP (true positive)',
        'trigger': '守卫检查 idx < 64 但写入 idx*8+8 可超出',
        'code': r'''/* 守卫不充分的堆溢出 — 边界检查写的是 ≤ 而非 <.
 *
 * cmp rcx, 64; ja → overflow → 但循环边界检查用 ≤ 64,
 * 第64次迭代写入 idx=63: offset=63*8+8=512 > alloc=512 → 恰好溢出.
 * Expected: TP (守卫存在但不足以防止溢出)
 */
#include <stdlib.h>
#include <string.h>

int main() {
    unsigned long long *buf = (unsigned long long *)malloc(512);
    if (!buf) return 1;
    /* 守卫: idx <= 64, 但 64*8=512, idx=63 时写 63*8..63*8+8=512 → 越界 */
    for (int idx = 0; idx <= 64; idx++) {
        buf[idx] = (unsigned long long)idx;  /* idx=64: overflow by 8 */
    }
    free(buf);
    return 0;
}
''',
    },
    {
        'id': 'sample04_cross_function_overflow',
        'title': 'CVE-2024-0004 Cross-Function Heap Overflow',
        'pattern': 'caller: malloc(64); callee: memset(p, X, 256)',
        'expected': 'TP (true positive)',
        'trigger': '跨函数: callee 的 size 参数(256) > caller 的 alloc(64)',
        'code': r'''/* 跨函数堆溢出 — caller 分配, callee 写入越界.
 *
 * caller allocates 64 bytes, passes to callee which writes 256.
 * 这是 heap-cve-14 类模式: 跨函数 size 参数 > alloc.
 * Expected: TP (cross-function detection needed)
 */
#include <stdlib.h>
#include <string.h>

static void process_buffer(char *buf, int len) {
    /* callee: 使用 len 而非原始 alloc size */
    memset(buf, 0x42, len);  /* len=256 > alloc=64 → OVERFLOW */
}

int main() {
    char *buf = (char *)malloc(64);
    if (!buf) return 1;
    process_buffer(buf, 256);
    free(buf);
    return 0;
}
''',
    },
    {
        'id': 'sample05_loop_cumulative_overflow',
        'title': 'CVE-2024-0005 Loop Cumulative Write Overflow',
        'pattern': 'for i in 0..N: memcpy(buf+offset, src, chunk) → 累积 > alloc',
        'expected': 'TP (true positive)',
        'trigger': '循环 16 次 × 64 字节 = 1024 > alloc(512)',
        'code': r'''/* 循环累积写入堆溢出.
 *
 * 每次写入 chunk_size, 循环 N 次, 累积 > alloc.
 * Expected: TP (loop-aware detection needed)
 */
#include <stdlib.h>
#include <string.h>

int main() {
    char *buf = (char *)malloc(512);
    if (!buf) return 1;
    int offset = 0;
    for (int i = 0; i < 16; i++) {
        /* 每次写 64 字节, 16×64=1024 > 512 → OVERFLOW */
        memset(buf + offset, 'A' + i, 64);
        offset += 64;
    }
    free(buf);
    return 0;
}
''',
    },
    {
        'id': 'sample06_sprintf_overflow',
        'title': 'CVE-2024-0006 sprintf Unbounded Write Overflow',
        'pattern': 'sprintf(malloc(32), "%s", user_input)',
        'expected': 'TP (true positive)',
        'trigger': 'sprintf 无界写入, 目标缓冲区仅32字节',
        'code': r'''/* sprintf 堆溢出 — 无界写入到 malloc 缓冲区.
 *
 * malloc(32) 作为 sprintf 的目标, 输入超过32字节 → OVERFLOW.
 * Expected: TP (sprintf/inline copy detection)
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main() {
    char *buf = (char *)malloc(32);
    if (!buf) return 1;
    /* sprintf: 无界写入, 输入 > 32 即溢出 */
    sprintf(buf, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  /* 44字节 */
                  "AAAAAAAAAAA");  /* 总计 55 > 32 → OVERFLOW */
    free(buf);
    return 0;
}
''',
    },
    {
        'id': 'sample07_memcpy_computed_size',
        'title': 'CVE-2024-0007 memcpy Computed Size Overflow',
        'pattern': 'malloc(user_size - 1); memcpy(buf, src, user_size)',
        'expected': 'TP (true positive)',
        'trigger': 'alloc_size = user_input - 1, copy_size = user_input → 差1字节溢出',
        'code': r'''/* memcpy 计算 size 溢出 — alloc 和 copy 使用不同的 size 变量.
 *
 * alloc = user_size - 1 (off-by-one), copy = user_size.
 * Expected: TP (memcpy size > alloc size)
 */
#include <stdlib.h>
#include <string.h>

int main() {
    int user_size = 128;
    int alloc_size = user_size - 1;  /* 127 */
    char *buf = (char *)malloc(alloc_size);
    if (!buf) return 1;
    /* copy_size(128) > alloc_size(127) → OVERFLOW by 1 byte */
    memset(buf, 0xFF, user_size);
    free(buf);
    return 0;
}
''',
    },
    {
        'id': 'sample08_alignment_padding_safe',
        'title': 'Alignment Padding Write (Safe)',
        'pattern': '写入在 ptmalloc2 对齐填充内, 实际不越界',
        'expected': 'TN (true negative) — 应判为 safe',
        'trigger': 'malloc(50)→usable(64), write at offset 56, size=8 → 56+8=64 ≤ 64, 安全',
        'code': r'''/* 对齐填充内的写入 — 应该判为 safe (消除 FP).
 *
 * malloc(50) 实际可用 64 字节 (ptmalloc2 对齐到16).
 * offset=56, size=8 → 56+8=64 ≤ usable(50)=64 → 安全.
 * 这是 FP 测试: 检测器若只看请求大小 50(而非 usable 64) 会误报.
 * Expected: TN (allocation-aware → safe)
 */
#include <stdlib.h>
#include <string.h>

int main() {
    char *buf = (char *)malloc(50);
    if (!buf) return 1;
    /* usable=64, 56+8=64 → 恰好在边界内 */
    memset(buf + 56, 0, 8);
    free(buf);
    return 0;
}
''',
    },
    {
        'id': 'sample09_strncpy_truncation_overflow',
        'title': 'CVE-2024-0009 strncpy Truncation → Overflow',
        'pattern': 'strncpy(buf, src, alloc_size) → 截断无 null term → 后续操作溢出',
        'expected': 'TP (true positive)',
        'trigger': 'strncpy 填满缓冲区, 无 null term, 后续 strcat 写入越界',
        'code': r'''/* strncpy 截断溢出 — 截断后缺少 null 终止符造成后续越界.
 *
 * strncpy(exact_size) 不添加 null, strlen(buf)=未定义 → strcat 越界.
 * Expected: TP (strncpy truncation aware)
 */
#include <stdlib.h>
#include <string.h>

int main() {
    char *buf = (char *)malloc(16);
    if (!buf) return 1;
    /* strncpy(dst, src, 16): 填满16字节, 不加 '\0' */
    strncpy(buf, "AAAAAAAAAAAAAAAAAAAAAAAA", 16);
    /* strlen(buf) 可能 > 15 → strcat 越界写入 */
    strcat(buf, "BB");  /* OVERFLOW: 写入位置 > buf+15 */
    free(buf);
    return 0;
}
''',
    },
    {
        'id': 'sample10_realloc_shrink_overflow',
        'title': 'CVE-2024-0010 realloc Shrink Then Overflow',
        'pattern': 'p=realloc(p, 32); memset(p, X, 64) — 旧 size 残留',
        'expected': 'TP (true positive)',
        'trigger': 'realloc 缩小到32, 仍按旧 size 64 写入',
        'code': r'''/* realloc 缩小后溢出 — 遗留旧 size 引用.
 *
 * p=realloc(p, 32) 缩小, 仍用旧 size=64 写入.
 * Expected: TP (realloc size tracking)
 */
#include <stdlib.h>
#include <string.h>

int main() {
    char *buf = (char *)malloc(64);
    if (!buf) return 1;
    memset(buf, 0, 64);
    /* realloc 缩小到 32 */
    buf = (char *)realloc(buf, 32);
    if (!buf) return 1;
    /* 仍按旧 size=64 写入 → OVERFLOW by 32 bytes */
    memset(buf, 'X', 64);
    free(buf);
    return 0;
}
''',
    },
    {
        'id': 'sample11_calloc_wraparound',
        'title': 'CVE-2024-0011 calloc nmemb*size Wraparound',
        'pattern': 'calloc(nmemb, size) → nmemb*size 回绕 → alloc 不足',
        'expected': 'TP (true positive)',
        'trigger': 'calloc(0x10000001, 256) → nmemb*size 回绕 32-bit → 小 alloc',
        'code': r'''/* calloc 溢出 — nmemb * size 乘法回绕.
 *
 * calloc(nmemb=0x10000001, size=256) → 乘积回绕 32-bit → alloc 小.
 * Expected: TP (calloc wraparound detection)
 */
#include <stdlib.h>
#include <string.h>

int main() {
    /* nmemb*size = 0x10000001*256 mod 2^32 = 256 → alloc 仅256字节 */
    char *buf = (char *)calloc(0x10000001, 256);
    if (!buf) return 1;
    /* 期望 nmemb*size 字节, 写入远超 alloc → OVERFLOW */
    memset(buf, 0, 512);
    free(buf);
    return 0;
}
''',
    },
    {
        'id': 'sample12_conditional_overflow',
        'title': 'CVE-2024-0012 Conditional Path Overflow',
        'pattern': 'if(safe) { write(64) } else { write(128) }, alloc=64',
        'expected': 'TP (true positive)',
        'trigger': 'else 分支 size=128 > alloc=64 → 条件溢出',
        'code': r'''/* 条件路径溢出 — 仅在特定分支溢出.
 *
 * alloc=64, safe 分支正常, unsafe 分支写入 128.
 * Expected: TP (path-sensitive detection)
 */
#include <stdlib.h>
#include <string.h>

int main() {
    int safe_mode = 0;  /* 0=unsafe path */
    char *buf = (char *)malloc(64);
    if (!buf) return 1;
    if (safe_mode) {
        memset(buf, 0, 32);   /* safe: 32 < 64 */
    } else {
        memset(buf, 0, 128);  /* OVERFLOW: 128 > 64 */
    }
    free(buf);
    return 0;
}
''',
    },
    {
        'id': 'sample13_multi_alloc_pointer_confusion',
        'title': 'CVE-2024-0013 Multi-Allocation Pointer Confusion',
        'pattern': 'p1=malloc(32); p2=malloc(64); memset(p1, X, 64) — 写到 p2 空间',
        'expected': 'TP (true positive)',
        'trigger': '对 p1 写 64 字节, 但 p1 仅分配 32 字节',
        'code': r'''/* 多分配指针混淆 — 误将小缓冲区的指针用于大写入.
 *
 * p1=malloc(32), p2=malloc(64), 但 memset 用的是 p1(32) 写入 64 字节.
 * Expected: TP (correct alloc site association)
 */
#include <stdlib.h>
#include <string.h>

int main() {
    char *p1 = (char *)malloc(32);
    char *p2 = (char *)malloc(64);
    if (!p1 || !p2) return 1;
    /* p1 仅 32 字节, 但写入 64 → OVERFLOW (溢出可能覆盖 p2) */
    memset(p1, 'X', 64);
    free(p1);
    free(p2);
    return 0;
}
''',
    },
    {
        'id': 'sample14_nested_struct_overflow',
        'title': 'CVE-2024-0014 Nested Struct Deep Offset Overflow',
        'pattern': 'malloc(sizeof(Outer)); outer->inner.data[256] = X — 深层偏移越界',
        'expected': 'TP (true positive)',
        'trigger': '嵌套 struct 的深层成员偏移 > sizeof(Outer)',
        'code': r'''/* 嵌套结构深层偏移堆溢出.
 *
 * Outer: { header[64], Inner inner }, Inner: { meta[32], data[256] }
 * sizeof(Outer) = 352, 但 outer->inner.data[256] 偏移可能=352 → 溢出.
 * Expected: TP (struct-aware offset tracking)
 */
#include <stdlib.h>
#include <string.h>

typedef struct {
    char meta[32];
    char data[256];
} Inner;

typedef struct {
    char header[64];
    Inner inner;
} Outer;

int main() {
    Outer *obj = (Outer *)malloc(sizeof(Outer));  /* 64+32+256=352 */
    if (!obj) return 1;
    /* sizeof(Outer)=352, data[0] offset=96, data[256] offset=352 → 溢出 */
    memset(obj->inner.data + 256, 0, 16);  /* OVERFLOW by 16 */
    free(obj);
    return 0;
}
''',
    },
    {
        'id': 'sample15_properly_guarded_safe',
        'title': 'Properly Guarded Write (Safe)',
        'pattern': 'malloc(64); if(idx < 64) buf[idx]=X — 有正确边界检查',
        'expected': 'TN (true negative) — 应判为 safe',
        'trigger': '显式边界检查 idx < 64 在 malloc(64) 前 → 安全',
        'code': r'''/* 正确守卫的写入 — 有有效的边界检查.
 *
 * malloc(64), 写入前检查 idx < 64 → 安全.
 * Expected: TN (guarded correctly → safe, no FP)
 */
#include <stdlib.h>
#include <string.h>

int main() {
    unsigned char *buf = (unsigned char *)malloc(64);
    if (!buf) return 1;
    int idx = 63;
    if (idx < 64) {  /* 守卫条件正确 */
        buf[idx] = 'X';  /* safe: idx=63 < alloc=64 */
    }
    free(buf);
    return 0;
}
''',
    },
    {
        'id': 'sample16_exact_boundary_safe',
        'title': 'Exact Boundary Write (Safe)',
        'pattern': 'malloc(64); memset(buf+60, 0, 4) — 60+4=64, 恰好在边界',
        'expected': 'TN (true negative) — 应判为 safe',
        'trigger': 'offset+size==alloc → 恰好不溢出, 应判 safe',
        'code': r'''/* 精确边界写入 — offset+size == alloc_size.
 *
 * malloc(64), offset=60, size=4 → 60+4=64 ≤ usable(64)=64 → safe.
 * Expected: TN (boundary-exact → safe, no FP)
 */
#include <stdlib.h>
#include <string.h>

int main() {
    char *buf = (char *)malloc(64);
    if (!buf) return 1;
    /* offset=60 + size=4 = 64, exact boundary → safe */
    memset(buf + 60, 0, 4);
    free(buf);
    return 0;
}
''',
    },
    {
        'id': 'sample17_large_offset_small_write',
        'title': 'Large Offset Small Write Near Boundary',
        'pattern': 'malloc(2112); write at offset 2048, 8 bytes → 2048+8=2056 ≤ 2112, safe',
        'expected': 'TN (true negative) — 应判为 safe',
        'trigger': 'offset=2048 很大但仍在 alloc 内 → 不应误判为溢出',
        'code': r'''/* 大偏移小写入 — offset 很大但仍在范围内.
 *
 * malloc(2112) → usable ≥ 2112, offset=2048, size=8 → 2056 ≤ 2112 → safe.
 * 这是 FP 测试: 检测器看到 offset=2048 (很大) 可能误判.
 * Expected: TN (large offset ≤ alloc → safe)
 */
#include <stdlib.h>
#include <string.h>

int main() {
    char *buf = (char *)malloc(2112);
    if (!buf) return 1;
    /* 2048+8=2056 ≤ 2112 → safe */
    memset(buf + 2048, 0, 8);
    free(buf);
    return 0;
}
''',
    },
    {
        'id': 'sample18_16bit_overflow_to_heap',
        'title': 'CVE-2024-0018 16-bit Size Overflow → Heap Overflow',
        'pattern': 'uint16_t size → overflow at 65536 → malloc(small) → write(original)',
        'expected': 'TP (true positive)',
        'trigger': '16-bit 回绕: uint16_t(65536) = 0 → alloc 0 或极小 → 写入越界',
        'code': r'''/* 16-bit 整数溢出 → 堆溢出.
 *
 * uint16_t size = 65536 wraps to 0, malloc(0) returns min chunk,
 * but write expects 65536 bytes → OVERFLOW.
 * Expected: TP (16-bit overflow → heap)
 */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int main() {
    uint16_t count = 0;  /* will overflow when set to 65536 */
    /* simulate: count = 65536 wrapping to 0 */
    count = 0;  /* wraps from 65536 */
    size_t alloc_size = count * 16;  /* 0 * 16 = 0 */
    char *buf = (char *)malloc(alloc_size ? alloc_size : 1);
    if (!buf) return 1;
    /* actual write target: count*16 bytes, but count wrapped → OVERFLOW */
    memset(buf, 'X', 65536U * 16);
    free(buf);
    return 0;
}
''',
    },
]


def write_sample(base_dir, sample):
    d = os.path.join(base_dir, sample['id'])
    os.makedirs(d, exist_ok=True)

    # C 源码
    with open(os.path.join(d, 'main.c'), 'w', encoding='utf-8') as f:
        f.write(sample['code'].lstrip('\n'))

    # Makefile
    makefile = f'''# {sample['title']}
# Pattern: {sample['pattern']}
# Expected: {sample['expected']}

CC = gcc
CFLAGS = -Wall -O0 -g -fno-builtin
TARGET = main

all: $(TARGET)

$(TARGET): main.c
\t$(CC) $(CFLAGS) -o $(TARGET) main.c

disasm: $(TARGET)
\tobjdump -d -M intel $(TARGET) > $(TARGET).asm

clean:
\trm -f $(TARGET) $(TARGET).asm

.PHONY: all disasm clean
'''
    with open(os.path.join(d, 'Makefile'), 'w', encoding='utf-8') as f:
        f.write(makefile)

    # README
    bin_path = os.path.join(d, 'main').replace('\\', '/')
    readme = f'''# {sample['title']}

# CVE Pattern
{sample['pattern']}

# Trigger Condition
{sample['trigger']}

# Expected Result
**{sample['expected']}**

# Validity
This is a valid test case because:
1. The heap overflow is reproducible when compiled as a standalone ELF
2. The binary contains recognizable patterns: malloc call + memory access
3. The overflow condition is clear and deterministic (no race conditions)
4. The sample isolates one specific detection challenge

# Compile
```sh
make          # compile with gcc -O0 -g
make disasm   # generate objdump output
```

# Binary
`{bin_path}` (ELF, unstripped, x86-64)
'''
    with open(os.path.join(d, 'README.md'), 'w', encoding='utf-8') as f:
        f.write(readme)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else 'test_samples'
    base = os.path.abspath(out)
    print(f'Generating {len(SAMPLES)} test samples → {base}')
    for s in SAMPLES:
        write_sample(base, s)
        print(f'  {s["id"]}: {s["title"]}')
    print(f'\nDone. {len(SAMPLES)} samples generated in {base}')
    print('To compile all: cd test_samples && for d in sample*/; do (cd "$d" && make); done')


if __name__ == '__main__':
    main()
