/**
 * CVE-2019-11479 — add overflow loop: loop accumulator wraps u16
 * 模式: loop_add
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

// loop_add: u16 accumulator wraps in loop
static volatile void *volatile_vuln_sink;  /* 阻止O2/Os编译期消除 */

__attribute__((noinline))
void v_2019_11479_mss_vuln(int count) {
    __asm__ __volatile__("" : "+r"(count));
    uint16_t total = 0;
    int n = count;
    for (int i = 0; i < n; i++) {
      total += 64;  /* wraps when n>1024 */
    }
    if (total > 0 && total < 8192) {
      char *buf = (char *)malloc(total);
      if (!buf) return;
      memset(buf, 0, total);
      volatile_vuln_sink = buf;
    __asm__ __volatile__("" : : "r"(buf) : "memory");
      free(buf);
    }
    printf("v_2019_11479_mss: done\n");
}

__attribute__((noinline))
void v_2019_11479_mss_safe(int count) {
    __asm__ __volatile__("" : "+r"(count));
    int n = count;
    if (n > 1024) {  /* 1024*64=65536 -> wraps u16 */
      printf("overflow rejected\n");
      return;
    }
    uint16_t total = 0;
    for (int i = 0; i < n; i++) total += 64;
    char *buf = (char *)malloc(total);
    if (!buf) return;
    memset(buf, 0, total);
    free(buf);
    printf("v_2019_11479_mss: ok\n");
}

int main(int argc, char **argv) {
    int count = 1073741824;
    if (argc > 1) count = atoi(argv[1]);
    printf("intof test\n");
    v_2019_11479_mss_vuln(count);
    v_2019_11479_mss_safe(count);
    return 0;
}
