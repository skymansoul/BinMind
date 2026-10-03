/*
 * HEAP-OVERFLOW-COND-03: 条件分支中的堆溢出 — 测试路径敏感分析。
 *
 * 模式: 在 if/else 分支中有不同的分配和写入路径。
 * 某个分支中分配大小不足, 另一分支正常。
 * 非路径敏感的分析会合并两个分支 → 误报或漏报。
 *
 * 此样本含1个真阳性溢出 + 1个误报触发点。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    int mode = (argc > 1) ? atoi(argv[1]) : 0;
    int size = (argc > 2) ? atoi(argv[2]) : 64;
    if (size <= 0) size = 64;

    char *buf;

    if (mode == 0) {
        /* 路径A: 安全路径 —— 分配足够大 */
        buf = malloc(256);
        if (!buf) return 1;
        memset(buf, 'A', size < 256 ? size : 256);
        printf("safe path: wrote %d bytes\n", size < 256 ? size : 256);
    } else {
        /* 路径B: 危险路径 —— 分配小, 写入大 */
        buf = malloc(32);       /* <-- 仅分配 32B */
        if (!buf) return 1;
        /* VULN: 写入可能超过 32B */
        memset(buf, 'B', size); /* <-- 若 size > 32, 溢出 */
        printf("risky path: wrote %d bytes into 32B buffer\n", size);
    }

    free(buf);
    return 0;
}
