/**
 * CVE-2014-2851 — u16 overflow: ICMP payload length calc wraps
 * 模式: u16_overflow
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

// u16_overflow: 16-bit mul wraps before promotion
static volatile void *volatile_vuln_sink;  /* 阻止O2/Os编译期消除 */

__attribute__((noinline))
void v_2014_2851_ping_vuln(int count) {
    __asm__ __volatile__("" : "+r"(count));
    uint16_t c16 = (uint16_t)count;
    size_t sz = (size_t)(c16 * sizeof(int));  /* Bug: 16-bit compute first */
    if (sz > 0 && sz < 65536) {
      char *buf = (char *)malloc(sz);
      if (!buf) return;
      memset(buf, 0, sz + 16);
      volatile_vuln_sink = buf;
    __asm__ __volatile__("" : : "r"(buf) : "memory");
      free(buf);
    }
    printf("v_2014_2851_ping: done\n");
}

__attribute__((noinline))
void v_2014_2851_ping_safe(int count) {
    __asm__ __volatile__("" : "+r"(count));
    uint16_t c16 = (uint16_t)count;
    size_t sz = (size_t)c16 * sizeof(int);  /* Correct: promote BEFORE mul */
    char *buf = (char *)malloc(sz);
    if (!buf) return;
    memset(buf, 0, sz);
    free(buf);
    printf("v_2014_2851_ping: ok\n");
}

int main(int argc, char **argv) {
    int count = 1073741824;
    if (argc > 1) count = atoi(argv[1]);
    printf("intof test\n");
    v_2014_2851_ping_vuln(count);
    v_2014_2851_ping_safe(count);
    return 0;
}
