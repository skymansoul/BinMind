/*
 * CVE-35: 早返回安全 — guard导致提前返回, 写入只在安全路径执行
 *
 * 模式: malloc(128); if(n > 100) return; memcpy(buf, src, 96);
 * 全局CJ: guard "n<=100" 被混入, 但写入96B, usable(128)=136
 *         96 <= 136 → 安全, 但guard可能干扰变量约束
 * PS-CJ:  返回路径无写入; 写入路径上 n<=100, write=96 <= usable 136 → SAFE
 *
 * 安全: memcpy 96B, malloc(128) usable=136, 96 <= 136 → SAFE
 * 对应: 类似 CVE-2018-6789 (Exim SMTP heap overflow, guarded path)
 * 检测预期: PROVEN_SAFE
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void process(char *buf, int n) {
    if (n > 100) return;
    memcpy(buf, "data", 96);
}

int main(void) {
    int n = 80;
    char *buf = (char *)malloc(128);
    if (!buf) return 1;

    process(buf, n);
    printf("early_return_safe: n=%d\n", n);
    free(buf);
    return 0;
}
