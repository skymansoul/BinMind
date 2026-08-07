/*
 * CVE-36: 早返回仍溢出 — guard导致提前返回但写入路径仍溢出
 *
 * 模式: malloc(32); if(n > 200) return; memcpy(buf, src, 64);
 * 全局CJ: guard "n<=200" 混入, 但写入64B, usable(32)=40
 *         64 > 40 → OVERFLOW, guard不影响常量比较
 * PS-CJ:  返回路径无写入; 写入路径上 n<=200, write=64 > usable 40 → OVERFLOW
 *
 * 溢出: malloc(32) usable=40, memcpy 64B > 40 → OVERFLOW
 * 对应: 类似 CVE-2019-2215 (Android binder heap overflow, early return)
 * 检测预期: PROVEN_OVERFLOW
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void process(char *buf, int n) {
    if (n > 200) return;
    memcpy(buf, "data", 64);
}

int main(void) {
    int n = 150;
    char *buf = (char *)malloc(32);
    if (!buf) return 1;

    process(buf, n);
    printf("early_return_overflow: n=%d\n", n);
    free(buf);
    return 0;
}
