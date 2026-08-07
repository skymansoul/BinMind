/**
 * CVE-2012-0809 — sprintf计算格式 栈溢出
 * 模式: sprintf_chain
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
void v_2012_0809_sudo_vuln(int count) {
    __asm__ __volatile__("" : "+r"(count));
    char buf[32];
    __asm__ __volatile__("" : "+r"(count));
    char *p = buf;
    p += sprintf(p, "hdr:%d:", count);
    p += sprintf(p, "%s", "AAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    volatile_vuln_sink = buf;
    printf("v_2012_0809_sudo: done\n");
}
__attribute__((noinline))
void v_2012_0809_sudo_safe(int count) {
    __asm__ __volatile__("" : "+r"(count));
    char buf[32];
    __asm__ __volatile__("" : "+r"(count));
    snprintf(buf, sizeof(buf), "hdr:%d:%s", count, "AAA");
    printf("v_2012_0809_sudo: ok\n");
}
int main(int argc, char **argv) {
    int count = 65536;
    if (argc > 1) count = atoi(argv[1]);
    printf("stack of test\n");
    v_2012_0809_sudo_vuln(count);
    v_2012_0809_sudo_safe(count);
    return 0;
}
