/**
 * CVE-2016-6187 — truncation: u64->u32 compat ioctl bypasses size check
 * 模式: truncation
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

// truncation: u64->u32 bypasses size check
static volatile void *volatile_vuln_sink;  /* 阻止O2/Os编译期消除 */

__attribute__((noinline))
void v_2016_6187_compat_vuln(int count) {
    __asm__ __volatile__("" : "+r"(count));
    uint64_t num_entries = (uint64_t)count * 7ULL + 0x100000001ULL;
    uint32_t count32 = (uint32_t)num_entries;  /* truncation! */
    size_t sz = (size_t)count32 * sizeof(int);
    if (sz < 65536) {  /* bypassed: count32 is small */
      char *buf = (char *)malloc(sz);
      if (!buf) return;
      for (uint64_t i = 0; i < num_entries && i < 100; i++) buf[i] = 0;
      volatile_vuln_sink = buf;
    __asm__ __volatile__("" : : "r"(buf) : "memory");
      free(buf);
    }
    printf("v_2016_6187_compat: done\n");
}

__attribute__((noinline))
void v_2016_6187_compat_safe(int count) {
    __asm__ __volatile__("" : "+r"(count));
    uint64_t num_entries = (uint64_t)count * 7ULL + 0x100000001ULL;
    if (num_entries > UINT32_MAX) {
      printf("overflow rejected\n");
      return;
    }
    uint32_t count32 = (uint32_t)num_entries;
    size_t sz = count32 * sizeof(int);
    char *buf = (char *)malloc(sz);
    if (!buf) return;
    memset(buf, 0, sz);
    free(buf);
    printf("v_2016_6187_compat: ok\n");
}

int main(int argc, char **argv) {
    int count = 1073741824;
    if (argc > 1) count = atoi(argv[1]);
    printf("intof test\n");
    v_2016_6187_compat_vuln(count);
    v_2016_6187_compat_safe(count);
    return 0;
}
