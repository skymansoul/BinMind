/**
 * CVE-2014-3610 — strncpy(buf,src,sizeof(buf)) 无null终止符
 * 模式: strncpy_offbyone
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
void v_2014_3610_kvm_vuln(int count) {
    __asm__ __volatile__("" : "+r"(count));
    char buf[32];
    __asm__ __volatile__("" : "+r"(count));
    char src[64];
    memset(src, 'A', sizeof(src) - 1);
    src[63] = 0;
    strncpy(buf, src, sizeof(buf));  /* sizeof(buf)无null终止符空间 */
    __asm__ __volatile__("" : : "r"(buf) : "memory");
    volatile_vuln_sink = buf;
    printf("v_2014_3610_kvm: done\n");
}
__attribute__((noinline))
void v_2014_3610_kvm_safe(int count) {
    __asm__ __volatile__("" : "+r"(count));
    char buf[32];
    __asm__ __volatile__("" : "+r"(count));
    char src[64];
    memset(src, 'A', sizeof(src) - 1);
    src[63] = 0;
    strncpy(buf, src, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = 0;
    printf("v_2014_3610_kvm: ok\n");
}
int main(int argc, char **argv) {
    int count = 65536;
    if (argc > 1) count = atoi(argv[1]);
    printf("stack of test\n");
    v_2014_3610_kvm_vuln(count);
    v_2014_3610_kvm_safe(count);
    return 0;
}
