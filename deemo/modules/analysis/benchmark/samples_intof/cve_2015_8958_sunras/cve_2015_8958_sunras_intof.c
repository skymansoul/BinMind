/**
 * CVE-2015-8958 — signed mul: (int)rows*(int)cols overflows int32
 * 模式: signed_mul
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

// signed_mul: int*int overflows int32
static volatile void *volatile_vuln_sink;  /* 阻止O2/Os编译期消除 */

__attribute__((noinline))
void v_2015_8958_sunras_vuln(int count) {
    __asm__ __volatile__("" : "+r"(count));
    int rows = count;
    int cols = count;
    int total = rows * cols;  /* signed overflow -> UB! */
    if (total > 0 && total < 8192) {
      char *buf = (char *)malloc(total);
      if (!buf) return;
      memset(buf, 0, total);
      volatile_vuln_sink = buf;
    __asm__ __volatile__("" : : "r"(buf) : "memory");
      free(buf);
    }
    printf("v_2015_8958_sunras: done\n");
}

__attribute__((noinline))
void v_2015_8958_sunras_safe(int count) {
    __asm__ __volatile__("" : "+r"(count));
    int rows = count;
    int cols = count;
    size_t total = (size_t)rows * (size_t)cols;  /* promote BEFORE mul */
    if (total > 65536) {
      printf("too large\n");
      return;
    }
    char *buf = (char *)malloc(total);
    if (!buf) return;
    memset(buf, 0, total);
    free(buf);
    printf("v_2015_8958_sunras: ok\n");
}

int main(int argc, char **argv) {
    int count = 1073741824;
    if (argc > 1) count = atoi(argv[1]);
    printf("intof test\n");
    v_2015_8958_sunras_vuln(count);
    v_2015_8958_sunras_safe(count);
    return 0;
}
