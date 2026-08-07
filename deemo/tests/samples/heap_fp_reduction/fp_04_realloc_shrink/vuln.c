/*
 * FP-04: realloc 缩小语义
 *
 * realloc(ptr, new_size) 若 new_size <= 原始大小, glibc 原地缩小不分配新块。
 * 检测器若不理解 realloc 语义, 可能对"旧指针+新大小"的后续访问误报。
 *
 * 预期: 基准检测器 → 可能误报
 *       增强管线 → realloc 语义过滤
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char *buf = malloc(256);
    if (!buf) return 1;
    memset(buf, 'A', 256);
    // 缩小到 64, glibc 可能原地操作
    buf = realloc(buf, 64);
    if (!buf) return 1;
    // 对缩小后的 buf 做 64B 写入 —— 安全
    memset(buf, 'B', 64);
    printf("realloc shrink result: %.64s\n", buf);
    free(buf);
    return 0;
}
