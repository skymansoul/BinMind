/**
 * CVE-2017-7269 — memcpy(stack_buf,src,oversize) 超界拷贝
 * 模式: memcpy_oversized
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
void v_2017_7269_iis_vuln(int count) {
    __asm__ __volatile__("" : "+r"(count));
    char buf[32];
    __asm__ __volatile__("" : "+r"(count));
    char src[512];
    memset(src, 'A', sizeof(src));
    size_t sz = (size_t)count;
    memcpy(buf, src, sz);  /* buf只有32字节, sz可很大 → 溢出 */
    __asm__ __volatile__("" : : "r"(buf) : "memory");
    volatile_vuln_sink = buf;
    printf("v_2017_7269_iis: done\n");
}
__attribute__((noinline))
void v_2017_7269_iis_safe(int count) {
    __asm__ __volatile__("" : "+r"(count));
    char buf[32];
    __asm__ __volatile__("" : "+r"(count));
    char src[512];
    memset(src, 'A', sizeof(src));
    size_t sz = (size_t)count;
    if (sz > sizeof(buf)) sz = sizeof(buf) - 1;
    memcpy(buf, src, sz);
    buf[sizeof(buf) - 1] = 0;
    printf("v_2017_7269_iis: ok\n");
}
int main(int argc, char **argv) {
    int count = 65536;
    if (argc > 1) count = atoi(argv[1]);
    printf("stack of test\n");
    v_2017_7269_iis_vuln(count);
    v_2017_7269_iis_safe(count);
    return 0;
}
