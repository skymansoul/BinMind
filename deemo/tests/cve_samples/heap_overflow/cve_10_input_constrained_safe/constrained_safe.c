/*
 * CVE-10: 输入受约束 — 安全但不做路径分析会误报
 *
 * 场景: size = atoi(argv[1]); if(size > 1024) size = 1024; buf = malloc(size);
 *       memcpy(buf, src, 2048) — 但 size 已被截断到 ≤ 1024
 * 浅层分析: 看到 malloc(size) with user input → 无法判断, 保守保留.
 * 路径约束分析: size ≤ 1024 (截断), alloc=size ≤ 1024 < 2048 → 确实溢出!
 *
 * 等等, 这里即使截断也是溢出. 让我改成安全的情况:
 * size 截断后, 写入也基于截断后的值.
 *
 * 正确场景: size 被截断到 ≤ 1024, memcpy 写入 1024B, alloc 对齐后 ≥ 1024 → 安全.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("usage: %s <size>\n", argv[0]);
        return 0;
    }

    int size = atoi(argv[1]);

    // 输入约束: 上限截断
    if (size > 1024) {
        size = 1024;
    }

    char *buf = (char *)malloc(size);
    if (!buf) return 1;

    // memcpy 使用截断后的 size — 安全!
    // alloc aligned = max(32, align_up(1024+16, 16)) = 1040, usable ≈ 1024
    // write = 1024 ≤ usable → 安全
    memset(buf, 0, size);

    printf("constrained safe: size=%d\n", size);
    free(buf);
    return 0;
}
