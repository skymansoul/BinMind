/*
 * CVE-12: 对齐边界堆溢出
 *
 * 模式: malloc(16) → usable=16 (chunk=32, header=16).
 *       offset=14 写入 4B → 14+4=18 > 16 → 溢出 2B 到 header.
 *       溢入 header 但仍在本 chunk 内 — 低严重度, 但仍是溢出.
 *
 * malloc(16) → chunk_size = max(32, align_up(16+16,16)) = 32
 * usable = 32-16 = 16. store at offset 14, size 4 → end=18 > 16.
 * 但这只是溢入相邻 chunk 的 header — 不是数据区.
 *
 * 预期: 分配器语义应标记为低置信度溢出 (仅触及 header)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buf = (char *)malloc(16);
    if (!buf) return 1;

    // offset=14, write=4B → 到 18. 在 usable 边界
    *(int *)(buf + 14) = 0x41414141;

    printf("alignment edge done\n");
    free(buf);
    return 0;
}
