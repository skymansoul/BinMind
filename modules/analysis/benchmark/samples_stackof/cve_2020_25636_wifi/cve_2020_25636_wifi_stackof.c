/**
 * CVE-2020-25636 — strcpy+strcat 累积溢出链
 * 模式: strcat_chain
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
void v_2020_25636_wifi_vuln(int count) {
    __asm__ __volatile__("" : "+r"(count));
    char buf[32];
    __asm__ __volatile__("" : "+r"(count));
    char src[512];
    memset(src, 'A', count < 512 ? count : 511);
    src[(count < 512 ? count : 511)] = 0;
    buf[0] = 0;
    strcat(buf, "prefix_");
    strcat(buf, src);  /* src可能很长 → 累积溢出 */
    volatile_vuln_sink = buf;
    printf("v_2020_25636_wifi: done\n");
}
__attribute__((noinline))
void v_2020_25636_wifi_safe(int count) {
    __asm__ __volatile__("" : "+r"(count));
    char buf[32];
    __asm__ __volatile__("" : "+r"(count));
    char src[512];
    memset(src, 'A', count < 20 ? count : 19);
    src[19] = 0;
    snprintf(buf, sizeof(buf), "prefix_%s", src);
    printf("v_2020_25636_wifi: ok\n");
}
int main(int argc, char **argv) {
    int count = 65536;
    if (argc > 1) count = atoi(argv[1]);
    printf("stack of test\n");
    v_2020_25636_wifi_vuln(count);
    v_2020_25636_wifi_safe(count);
    return 0;
}
