/*
 * FP-02: 路径约束保护
 *
 * 分配大小由用户输入控制, 但在 malloc 前经过 if(size>256) size=256 约束。
 * 路径不敏感的分析会看到 malloc(size) 中的动态参数并标记为危险,
 * 但实际所有路径上 size ≤ 256, 而分配+写入的范围被约束保证安全。
 *
 * 预期: 基准检测器 → 误报 (动态分配大小)
 *       增强管线 → 正确过滤 (路径约束保证上限)
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int process(int user_len) {
    int size = user_len;
    if (size > 256) size = 256;
    if (size < 0) size = 0;
    char *buf = malloc(size);
    if (!buf) return -1;
    // memcpy 的大小受 size 约束, 不超过 256
    memcpy(buf, "safe_data", 9);
    printf("processed: %s\n", buf);
    free(buf);
    return 0;
}

int main(void) {
    process(512);  // 输入大于 256, 但被约束
    process(128);  // 正常输入
    return 0;
}
