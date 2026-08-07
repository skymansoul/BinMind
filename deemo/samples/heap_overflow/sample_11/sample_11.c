/*
 * sample_11 — 条件路径堆溢出.
 *
 * 漏洞只在特定条件路径上触发 — 测试路径敏感分析的区分能力.
 *
 * 路径 A (size <= 64): 安全 — 不溢出.
 * 路径 B (size > 64): 危险 — 分配64但按size写入.
 *
 * 简单静态分析会合并两条路径 → 报告"可能"溢出.
 * 路径敏感分析应该区分为两个独立场景.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    int size = (argc > 1) ? atoi(argv[1]) : 32;

    char *buf = (char *)malloc(64);
    if (!buf) return 1;

    if (size <= 64) {
        /* 安全路径: size 在分配范围内 */
        memset(buf, 'S', size);
        printf("safe: wrote %d bytes\n", size);
    } else {
        /* 危险路径: size > 64, 但缓冲区只有64字节 */
        memset(buf, 'D', size);  /* 堆溢出! */
        printf("DANGER: wrote %d bytes into 64-byte buffer\n", size);
    }

    free(buf);
    return 0;
}
