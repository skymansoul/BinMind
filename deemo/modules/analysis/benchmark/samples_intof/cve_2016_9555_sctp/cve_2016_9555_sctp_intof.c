/**
 * CVE-2016-9555 — signed negative: ssize_t bypasses negative check, becomes huge size_t
 * 模式: signed_negative
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

// signed_negative: negative ssize_t -> huge size_t
static volatile void *volatile_vuln_sink;  /* 阻止O2/Os编译期消除 */

__attribute__((noinline))
void v_2016_9555_sctp_vuln(int count) {
    __asm__ __volatile__("" : "+r"(count));
    ssize_t len = (ssize_t)count;  /* count is volatile, may be large */
    int narrow = (int)(unsigned int)count;  /* truncate then sign-extend */
    len = (ssize_t)narrow;
    size_t sz = (size_t)len;  /* negative -> huge size_t */
    if (sz > 0 && sz < 65536) {  /* bypassed: sz is huge */
      char *buf = (char *)malloc(sz);
      if (!buf) return;
      memset(buf, 0, 16);
      volatile_vuln_sink = buf;
    __asm__ __volatile__("" : : "r"(buf) : "memory");
      free(buf);
    }
    printf("v_2016_9555_sctp: done\n");
}

__attribute__((noinline))
void v_2016_9555_sctp_safe(int count) {
    __asm__ __volatile__("" : "+r"(count));
    ssize_t len = (ssize_t)count;
    if (len < 0 || len > 65536) {
      printf("invalid len\n");
      return;
    }
    size_t sz = (size_t)len;
    char *buf = (char *)malloc(sz);
    if (!buf) return;
    memset(buf, 0, sz);
    free(buf);
    printf("v_2016_9555_sctp: ok\n");
}

int main(int argc, char **argv) {
    int count = 1073741824;
    if (argc > 1) count = atoi(argv[1]);
    printf("intof test\n");
    v_2016_9555_sctp_vuln(count);
    v_2016_9555_sctp_safe(count);
    return 0;
}
