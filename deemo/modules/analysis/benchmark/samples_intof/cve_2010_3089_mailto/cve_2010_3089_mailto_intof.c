/**
 * CVE-2010-3089 — mul overflow: count*sizeof(T) wraps before malloc
 * 模式: mul_overflow
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

// mul_overflow: count*sizeof(T) wraps
static volatile void *volatile_vuln_sink;  /* 阻止O2/Os编译期消除 */

__attribute__((noinline))
void v_2010_3089_mailto_vuln(int count) {
    __asm__ __volatile__("" : "+r"(count));
    size_t sz = (size_t)count * sizeof(int);
    if (sz < 4096) {  /* guard bypassed when sz wraps to 0 */
      char *buf = (char *)malloc(sz);
      if (!buf) return;
      memset(buf, 0, sz > 0 ? sz : 4096);  /* write beyond alloc */
      volatile_vuln_sink = buf;
    __asm__ __volatile__("" : : "r"(buf) : "memory");
      free(buf);
    }
    printf("v_2010_3089_mailto: done\n");
}

__attribute__((noinline))
void v_2010_3089_mailto_safe(int count) {
    __asm__ __volatile__("" : "+r"(count));
    size_t sz = (size_t)count * sizeof(int);
    if (sz / sizeof(int) != (size_t)count) {
      printf("overflow rejected\n");
      return;
    }
    char *buf = (char *)malloc(sz);
    if (!buf) return;
    memset(buf, 0, sz);
    free(buf);
    printf("v_2010_3089_mailto: ok\n");
}

int main(int argc, char **argv) {
    int count = 1073741824;
    if (argc > 1) count = atoi(argv[1]);
    printf("intof test\n");
    v_2010_3089_mailto_vuln(count);
    v_2010_3089_mailto_safe(count);
    return 0;
}
