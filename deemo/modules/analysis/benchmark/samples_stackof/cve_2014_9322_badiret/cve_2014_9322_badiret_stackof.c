/**
 * CVE-2014-9322 — gets(stack_buf) 无界读取
 * 模式: gets
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
void v_2014_9322_badiret_vuln(int count) {
    __asm__ __volatile__("" : "+r"(count));
    char buf[32];
    __asm__ __volatile__("" : "+r"(count));
    char src[256];
    memset(src, 'A', count < 256 ? count : 255);
    src[(count < 256 ? count : 255)] = 0;
    gets(buf);  /* 无界: 输入>32字节 → 栈溢出 */
    volatile_vuln_sink = buf;
    printf("v_2014_9322_badiret: done\n");
}
__attribute__((noinline))
void v_2014_9322_badiret_safe(int count) {
    __asm__ __volatile__("" : "+r"(count));
    char buf[32];
    __asm__ __volatile__("" : "+r"(count));
    char src[256];
    memset(src, 'A', count < 32 ? count : 31);
    src[31] = 0;
    strncpy(buf, src, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = 0;
    printf("v_2014_9322_badiret: ok\n");
}
int main(int argc, char **argv) {
    int count = 65536;
    if (argc > 1) count = atoi(argv[1]);
    printf("stack of test\n");
    v_2014_9322_badiret_vuln(count);
    v_2014_9322_badiret_safe(count);
    return 0;
}
