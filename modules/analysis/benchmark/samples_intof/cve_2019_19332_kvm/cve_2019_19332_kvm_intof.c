/**
 * CVE-2019-19332 — calloc dual: nmemb*size wraps inside calloc wrapper
 * 模式: calloc_dual
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

// calloc_dual: nmemb*size wraps in calloc wrapper
static volatile void *volatile_vuln_sink;  /* 阻止O2/Os编译期消除 */

__attribute__((noinline))
void v_2019_19332_kvm_vuln(int count) {
    __asm__ __volatile__("" : "+r"(count));
    size_t nmemb = (size_t)count;
    size_t elem_size = 16;
    size_t total = nmemb * elem_size;  /* wraps silently! */
    if (total < 65536 && total > 0) {
      char *buf = (char *)calloc(1, total);
      if (!buf) return;
      memset(buf, 0, total > 0 ? total : 65536);
      volatile_vuln_sink = buf;
    __asm__ __volatile__("" : : "r"(buf) : "memory");
      free(buf);
    }
    printf("v_2019_19332_kvm: done\n");
}

__attribute__((noinline))
void v_2019_19332_kvm_safe(int count) {
    __asm__ __volatile__("" : "+r"(count));
    size_t nmemb = (size_t)count;
    size_t elem_size = 16;
    if (nmemb > SIZE_MAX / elem_size) {
      printf("overflow rejected\n");
      return;
    }
    size_t total = nmemb * elem_size;
    char *buf = (char *)calloc(1, total);
    if (!buf) return;
    memset(buf, 0, total);
    free(buf);
    printf("v_2019_19332_kvm: ok\n");
}

int main(int argc, char **argv) {
    int count = 1073741824;
    if (argc > 1) count = atoi(argv[1]);
    printf("intof test\n");
    v_2019_19332_kvm_vuln(count);
    v_2019_19332_kvm_safe(count);
    return 0;
}
