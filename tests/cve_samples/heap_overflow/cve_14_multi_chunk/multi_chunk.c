/*
 * CVE-14: 多 Chunk 堆溢出 — 跨越 chunk 边界
 *
 * 模式: 连续分配两个 chunk, 写入第一个时溢出到第二个的数据区
 * 触发: p=malloc(32); q=malloc(32); memset(p, X, 48) → 溢出 16B 到 q
 *
 * 连续 chunk 布局:
 *   p_chunk @ 0x0, size=48 (32+16header), usable=32
 *   q_chunk @ 0x30, size=48, usable=32
 *   memset(p, 48) 从 p+0 写入到 p+47, 覆盖了 q 的 header (offset 32-47)
 *
 * 预期: Heap layout oracle 应识别连续分配, 确认溢出跨越 chunk 边界
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *p = (char *)malloc(32);
    char *q = (char *)malloc(32);
    if (!p || !q) return 1;

    strcpy(q, "safe data");

    // 写入 48B 到 32B 的 p → 溢出到 q 的 header 和 data
    memset(p, 'P', 48);

    printf("p[0]=%c q[0]=%c (should be P)\n", p[0], q[0]);
    free(p);
    free(q);
    return 0;
}
