/**
 * CVE-2019-9213 — while循环拷贝到栈缓冲区
 * 模式: loop_copy
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
void v_2019_9213_nullptr_vuln(int count) {
    __asm__ __volatile__("" : "+r"(count));
    char buf[32];
    __asm__ __volatile__("" : "+r"(count));
    char src[256];
    memset(src, 'B', count < 256 ? count : 255);
    src[(count < 256 ? count : 255)] = 0;
    size_t cp_len = (size_t)(count + 1);  /* BUG: off-by-one, count+1应-1 */
    memcpy(buf, src, cp_len);  /* cp_len至少1, count=65536→cp_len=65537>32溢出 */
    __asm__ __volatile__("" : : "r"(buf) : "memory");
    volatile_vuln_sink = buf;
    printf("v_2019_9213_nullptr: done\n");
}
__attribute__((noinline))
void v_2019_9213_nullptr_safe(int count) {
    __asm__ __volatile__("" : "+r"(count));
    char buf[32];
    __asm__ __volatile__("" : "+r"(count));
    char src[256];
    memset(src, 'B', count < 32 ? count : 31);
    src[31] = 0;
    size_t cp_len = (size_t)count;
    if (cp_len > sizeof(buf) - 1) cp_len = sizeof(buf) - 1;
    memcpy(buf, src, cp_len);
    buf[cp_len] = 0;
    printf("v_2019_9213_nullptr: ok\n");
}
int main(int argc, char **argv) {
    int count = 65536;
    if (argc > 1) count = atoi(argv[1]);
    printf("stack of test\n");
    v_2019_9213_nullptr_vuln(count);
    v_2019_9213_nullptr_safe(count);
    return 0;
}
