/**
 * CVE-2018-1000026 — shift overflow: 1<<n with n>31 wraps int
 * 模式: shl_overflow
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

// shl_overflow: 1<<n wraps when n>=32
static volatile void *volatile_vuln_sink;  /* 阻止O2/Os编译期消除 */

__attribute__((noinline))
void v_2018_1000026_bcm_vuln(int count) {
    __asm__ __volatile__("" : "+r"(count));
    int shift = count % 64;  /* could be 32..63 */
    int sz = 1 << shift;  /* wraps to 0/negative */
    if (sz > 0 && sz < 4096) {
      char *buf = (char *)malloc(sz);
      if (!buf) return;
      memset(buf, 0, abs(sz));
      volatile_vuln_sink = buf;
    __asm__ __volatile__("" : : "r"(buf) : "memory");
      free(buf);
    }
    printf("v_2018_1000026_bcm: done\n");
}

__attribute__((noinline))
void v_2018_1000026_bcm_safe(int count) {
    __asm__ __volatile__("" : "+r"(count));
    int shift = count % 64;
    if (shift >= 31) {
      printf("shift too large\n");
      return;
    }
    int sz = 1 << shift;
    char *buf = (char *)malloc(sz);
    if (!buf) return;
    memset(buf, 0, sz);
    free(buf);
    printf("v_2018_1000026_bcm: ok\n");
}

int main(int argc, char **argv) {
    int count = 1073741824;
    if (argc > 1) count = atoi(argv[1]);
    printf("intof test\n");
    v_2018_1000026_bcm_vuln(count);
    v_2018_1000026_bcm_safe(count);
    return 0;
}
