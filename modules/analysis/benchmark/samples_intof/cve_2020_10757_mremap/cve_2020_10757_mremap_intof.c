/**
 * CVE-2020-10757 — shift+mul: nr<<12 wraps before page alloc
 * 模式: shl_mul
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

// shl_mul: nr<<12 wraps before page alloc
static volatile void *volatile_vuln_sink;  /* 阻止O2/Os编译期消除 */

__attribute__((noinline))
void v_2020_10757_mremap_vuln(int count) {
    __asm__ __volatile__("" : "+r"(count));
    int nr_pages = count;
    size_t sz = (size_t)(nr_pages << 12);  /* wraps when nr>=0x100000 */
    if (sz > 0 && sz < 0x100000) {
      char *buf = (char *)malloc(sz);
      if (!buf) return;
      memset(buf, 0, sz);
      volatile_vuln_sink = buf;
    __asm__ __volatile__("" : : "r"(buf) : "memory");
      free(buf);
    }
    printf("v_2020_10757_mremap: done\n");
}

__attribute__((noinline))
void v_2020_10757_mremap_safe(int count) {
    __asm__ __volatile__("" : "+r"(count));
    int nr_pages = count;
    if (nr_pages > 0xFFFFF) {
      printf("overflow rejected\n");
      return;
    }
    size_t sz = (size_t)nr_pages << 12;
    char *buf = (char *)malloc(sz);
    if (!buf) return;
    memset(buf, 0, sz);
    free(buf);
    printf("v_2020_10757_mremap: ok\n");
}

int main(int argc, char **argv) {
    int count = 1073741824;
    if (argc > 1) count = atoi(argv[1]);
    printf("intof test\n");
    v_2020_10757_mremap_vuln(count);
    v_2020_10757_mremap_safe(count);
    return 0;
}
