/**
 * CVE-2018-14634 — scanf("%s",buf) 无界输入到栈
 * 模式: scanf_pct_s
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
void v_2018_14634_kernel_vuln(int count) {
    __asm__ __volatile__("" : "+r"(count));
    char buf[32];
    __asm__ __volatile__("" : "+r"(count));
    char src[256];
    memset(src, 'A', count < 256 ? count : 255);
    src[(count < 256 ? count : 255)] = 0;
    sscanf(src, "%s", buf);  /* sscanf(buf, "%s", stack_buf) 无界 */
    volatile_vuln_sink = buf;
    printf("v_2018_14634_kernel: done\n");
}
__attribute__((noinline))
void v_2018_14634_kernel_safe(int count) {
    __asm__ __volatile__("" : "+r"(count));
    char buf[32];
    __asm__ __volatile__("" : "+r"(count));
    char src[64];
    memset(src, 'A', 30); src[30]=0;
    snprintf(buf, sizeof(buf), "%s", src);
    printf("v_2018_14634_kernel: ok\n");
}
int main(int argc, char **argv) {
    int count = 65536;
    if (argc > 1) count = atoi(argv[1]);
    printf("stack of test\n");
    v_2018_14634_kernel_vuln(count);
    v_2018_14634_kernel_safe(count);
    return 0;
}
