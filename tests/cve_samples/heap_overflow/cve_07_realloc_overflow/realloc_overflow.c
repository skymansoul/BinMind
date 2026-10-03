/*
 * CVE-07: realloc 堆溢出
 *
 * 模式: p=malloc(64); p=realloc(p, smaller); write past new size
 * 触发: 初始分配 64B, realloc 缩小为 16B, 仍按 64B 使用 → 溢出
 *
 * 对应真实 CVE: CVE-2019-17596 (Go crypto/dsa realloc issue)
 * 检测预期: realloc 后大小更新 — heap_context_tracker 应感知
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buf = (char *)malloc(64);
    if (!buf) return 1;

    // 缩小分配: 64B → 16B
    buf = (char *)realloc(buf, 16);
    if (!buf) return 1;

    // 仍按旧大小 64B 写入 → 溢出 48B
    memset(buf, 'X', 64);

    printf("realloc overflow done\n");
    free(buf);
    return 0;
}
