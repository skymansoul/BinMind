/**
 * CVE-2016-7117 — recv(sock,buf,size) 网络数据超界
 * 模式: recv_oversized
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
void v_2016_7117_recv_vuln(int count) {
    __asm__ __volatile__("" : "+r"(count));
    char buf[32];
    __asm__ __volatile__("" : "+r"(count));
    char src[4096];
    memset(src, 'C', sizeof(src));
    size_t sz = (size_t)count;  /* 网络传来的大小字段 */
    memcpy(buf, src, sz);  /* sz来自网络 → recv-like溢出 */
    __asm__ __volatile__("" : : "r"(buf) : "memory");
    volatile_vuln_sink = buf;
    printf("v_2016_7117_recv: done\n");
}
__attribute__((noinline))
void v_2016_7117_recv_safe(int count) {
    __asm__ __volatile__("" : "+r"(count));
    char buf[32];
    __asm__ __volatile__("" : "+r"(count));
    char src[4096];
    memset(src, 'C', sizeof(src));
    size_t sz = (size_t)count;
    if (sz > sizeof(buf)) sz = sizeof(buf) - 1;
    memcpy(buf, src, sz);
    buf[sizeof(buf) - 1] = 0;
    printf("v_2016_7117_recv: ok\n");
}
int main(int argc, char **argv) {
    int count = 65536;
    if (argc > 1) count = atoi(argv[1]);
    printf("stack of test\n");
    v_2016_7117_recv_vuln(count);
    v_2016_7117_recv_safe(count);
    return 0;
}
