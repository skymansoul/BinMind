/*
 * CVE-39: 循环guard跨路径 — guard在函数A, 循环写入在函数B, guard路径不包含写入
 *
 * 模式:
 *   alloc_and_guard(n): if(n>100) return NULL; return malloc(n);
 *   write_loop(buf, n): for(i<n) buf[i] = x;
 *   main: n=80; buf = alloc_and_guard(n); write_loop(buf, n);
 *
 * 全局CJ: guard "n<=100" 传播到写入函数, write_end = n*1 = 80 <= usable(80)=88 → SAFE
 *         但guard路径(alloc函数)和写入路径(write函数)不同
 * PS-CJ:  写入路径上n=80(被guard约束后), loop_write=80 <= usable 88 → SAFE
 *
 * 安全: n=80, usable(80)=88, loop_write_end=80*1=80 <= 88 → SAFE
 * 对应: 类似 CVE-2017-7269 (IIS WebDAV heap overflow, cross-function guard)
 * 检测预期: PROVEN_SAFE
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *alloc_and_guard(int n) {
    if (n > 100) return NULL;
    return (char *)malloc(n);
}

void write_loop(char *buf, int n) {
    int i;
    for (i = 0; i < n; i++) {
        buf[i] = 'L';
    }
}

int main(void) {
    int n = 80;
    char *buf = alloc_and_guard(n);
    if (!buf) return 1;

    write_loop(buf, n);
    printf("loop_guard_cross_path: n=%d\n", n);
    free(buf);
    return 0;
}
