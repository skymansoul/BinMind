/**
 * CVE-2019-14814 — snprintf(buf,err_size,...) 大小误算
 * 模式: snprintf_miscalc
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
void v_2019_14814_mwifiex_vuln(int count) {
    __asm__ __volatile__("" : "+r"(count));
    char buf[32];
    __asm__ __volatile__("" : "+r"(count));
    size_t wrong_size = (size_t)(count + 32);  /* 故意计算错误 */
    snprintf(buf, wrong_size, "%s", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    volatile_vuln_sink = buf;
    printf("v_2019_14814_mwifiex: done\n");
}
__attribute__((noinline))
void v_2019_14814_mwifiex_safe(int count) {
    __asm__ __volatile__("" : "+r"(count));
    char buf[32];
    __asm__ __volatile__("" : "+r"(count));
    snprintf(buf, sizeof(buf), "%s", "short_string");
    printf("v_2019_14814_mwifiex: ok\n");
}
int main(int argc, char **argv) {
    int count = 65536;
    if (argc > 1) count = atoi(argv[1]);
    printf("stack of test\n");
    v_2019_14814_mwifiex_vuln(count);
    v_2019_14814_mwifiex_safe(count);
    return 0;
}
