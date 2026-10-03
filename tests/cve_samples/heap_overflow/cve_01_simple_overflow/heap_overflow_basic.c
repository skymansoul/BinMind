/*
 * CVE-01: 基础堆溢出 — malloc(N) 后写入超过 N 字节
 *
 * 模式: 固定大小分配, 固定偏移写入超过分配大小
 * 触发: 分配 64B, 在 offset=72 处写入 8B → 溢出 16B
 *
 * 对应真实 CVE: 类似 CVE-2019-13135 (ImageMagick heap overflow)
 * 检测预期: 静态分析应检出 (offset 72 > alloc 64), 分配器语义无法过滤
 *   (72+8=80 > 32 对齐最小chunk, 实际溢出)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buf = (char *)malloc(64);
    if (!buf) return 1;

    // 安全写入
    memset(buf, 0, 64);

    // 溢出写入: offset 72 超出 64B 分配
    // store [buf + 72] ← 触发检测
    *(long *)(buf + 72) = 0x4141414141414141L;

    printf("overflow done\n");
    free(buf);
    return 0;
}
