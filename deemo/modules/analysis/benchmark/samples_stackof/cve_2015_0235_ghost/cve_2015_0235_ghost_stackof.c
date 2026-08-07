/**
 * CVE-2015-0235 — sprintf(buf,fmt,...) 无界格式化输出
 * 模式: sprintf
 *
 * 对静态分析的挑战:
 *   1. 栈缓冲区地址识别 (lea rcx,[rbp-N])
 *   2. 危险函数调用检测 (gets/strcpy/sprintf/memcpy)
 *   3. 写入大小 vs 缓冲区容量比较
 *   4. O2/Os优化后的代码模式保持
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

static volatile void *volatile_vuln_sink;  /* 阻止O2/Os编译期消除 */

__attribute__((noinline))
void v_2015_0235_ghost_vuln(int count) {
    __asm__ __volatile__("" : "+r"(count));
    char buf[32];
    __asm__ __volatile__("" : "+r"(count));
    const char *fmt = count > 100 ? "%064d" : "%s";
    sprintf(buf, fmt, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    volatile_vuln_sink = buf;
    printf("v_2015_0235_ghost: done\n");
}
__attribute__((noinline))
void v_2015_0235_ghost_safe(int count) {
    __asm__ __volatile__("" : "+r"(count));
    char buf[32];
    __asm__ __volatile__("" : "+r"(count));
    snprintf(buf, sizeof(buf), "%d", count);
    printf("v_2015_0235_ghost: ok\n");
}
int main(int argc, char **argv) {
    int count = 65536;
    if (argc > 1) count = atoi(argv[1]);
    printf("stack of test\n");
    v_2015_0235_ghost_vuln(count);
    v_2015_0235_ghost_safe(count);
    return 0;
}
