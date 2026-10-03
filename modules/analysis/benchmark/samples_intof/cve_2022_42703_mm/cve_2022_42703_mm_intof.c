/**
 * CVE-2022-42703 — add+sub underflow: len+addr overflows then underflows check
 * 模式: add_underflow
 *
 * 对静态分析的挑战:
 *   1. 溢出算术指令 (imul/shl/add) 的结果追踪
 *   2. 跨寄存器/栈槽的标记传播
 *   3. 编译器优化 (O2/Os) 后的模式识别
 *   4. 宽度转换 (32→64, 16→32) 的精确追踪
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// add_underflow: len+addr wraps 64-bit
static volatile void *volatile_vuln_sink;  /* 阻止O2/Os编译期消除 */

__attribute__((noinline))
void v_2022_42703_mm_vuln(int count) {
    __asm__ __volatile__("" : "+r"(count));
    uint64_t addr = 0xFFFFFFFFFFFFFF00ULL;
    uint64_t len = (uint64_t)count;
    uint64_t end = addr + len;  /* wraps on 64-bit! */
    size_t sz = (size_t)(end - addr);
    if (sz == len && sz < 4096) {  /* sz!=len when wraps */
      char *buf = (char *)malloc(sz);
      if (!buf) return;
      memset(buf, 0, sz);
      volatile_vuln_sink = buf;
    __asm__ __volatile__("" : : "r"(buf) : "memory");
      free(buf);
    }
    printf("v_2022_42703_mm: done\n");
}

__attribute__((noinline))
void v_2022_42703_mm_safe(int count) {
    __asm__ __volatile__("" : "+r"(count));
    uint64_t addr = 0xFFFFFFFFFFFFFF00ULL;
    uint64_t len = (uint64_t)count;
    if (len > UINT64_MAX - addr) {
      printf("overflow rejected\n");
      return;
    }
    uint64_t end = addr + len;
    size_t sz = (size_t)(end - addr);
    char *buf = (char *)malloc(sz);
    if (!buf) return;
    memset(buf, 0, sz);
    free(buf);
    printf("v_2022_42703_mm: ok\n");
}

int main(int argc, char **argv) {
    int count = 1073741824;
    if (argc > 1) count = atoi(argv[1]);
    printf("intof test\n");
    v_2022_42703_mm_vuln(count);
    v_2022_42703_mm_safe(count);
    return 0;
}
