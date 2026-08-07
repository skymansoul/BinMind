/**
 * CVE-2017-7184 — addition overflow: offset+len wraps u32
 * 模式: add_overflow
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

// add_overflow: offset+len wraps u32
static volatile void *volatile_vuln_sink;  /* 阻止O2/Os编译期消除 */

__attribute__((noinline))
void v_2017_7184_xfrm_vuln(int count) {
    __asm__ __volatile__("" : "+r"(count));
    uint32_t offset = (uint32_t)count * 256U + 0xFFFFFF00U;  /* offset depends on count */
    uint32_t len = (uint32_t)(count + 256);
    uint32_t end = offset + len;  /* wraps when count large enough */
    if (end < offset) {  /* overflow detected: end wrapped around */
      char *buf = (char *)malloc(end);  /* end is small after wrap */
      if (!buf) return;
      memcpy(buf, "data", 4);  /* write to small buffer */
      volatile_vuln_sink = buf;
    __asm__ __volatile__("" : : "r"(buf) : "memory");
      free(buf);
    }
    printf("v_2017_7184_xfrm: done\n");
}

__attribute__((noinline))
void v_2017_7184_xfrm_safe(int count) {
    __asm__ __volatile__("" : "+r"(count));
    uint32_t offset = (uint32_t)count * 256U + 0xFFFFFF00U;
    uint32_t len = (uint32_t)(count + 256);
    if (len > UINT32_MAX - offset) {
      printf("overflow rejected\n");
      return;
    }
    uint32_t end = offset + len;
    char *buf = (char *)malloc(end);
    if (!buf) return;
    memcpy(buf, "data", 4);
    free(buf);
    printf("v_2017_7184_xfrm: ok\n");
}

int main(int argc, char **argv) {
    int count = 1073741824;
    if (argc > 1) count = atoi(argv[1]);
    printf("intof test\n");
    v_2017_7184_xfrm_vuln(count);
    v_2017_7184_xfrm_safe(count);
    return 0;
}
