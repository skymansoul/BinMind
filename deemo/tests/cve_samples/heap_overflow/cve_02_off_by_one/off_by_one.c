/*
 * CVE-02: Off-By-One 堆溢出
 *
 * 模式: 循环写入 N+1 个元素到 N 大小的缓冲区
 * 触发: malloc(128), 循环 129 次写入 → 越界 1 字节
 *
 * 对应真实 CVE: CVE-2014-0160 (Heartbleed 的变体模式)
 * 检测预期: 循环上界推断应检出 (inferred bound 129 > alloc 128)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    int count = 129;
    char *buf = (char *)malloc(128);
    if (!buf) return 1;

    // Off-by-one: 循环写入 129 字节到 128B 缓冲区
    for (int i = 0; i < count; i++) {
        buf[i] = (char)i;
    }

    printf("off-by-one done\n");
    free(buf);
    return 0;
}
