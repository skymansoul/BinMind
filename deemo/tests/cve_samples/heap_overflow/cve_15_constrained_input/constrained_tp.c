/*
 * CVE-15: 有约束但仍溢出
 *
 * 场景: 输入约束到 ≤ 256, 但分配后写入 512B → 仍溢出
 * 浅层分析可能看到 if(size>256)size=256 约束 → 误判为安全
 * 但 256 < 512 → 仍然溢出!
 *
 * 这是FP过滤的危险边界: 路径约束证明 safe 的前提是
 * 约束后的值能容纳写入. 256 vs 512 显然不能.
 *
 * 预期: 路径约束 + Z3 → 证明 sat (溢出可能) → 保留 (非误报)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    int size = 512;
    if (argc > 1) size = atoi(argv[1]);

    // 约束: 上限 256
    if (size > 256) {
        size = 256;
    }

    char *buf = (char *)malloc(size);
    if (!buf) return 1;

    // 写入 512B — 超过约束后的上限 256 → 仍溢出!
    memset(buf, 'D', 512);

    printf("constrained but overflow: size=%d\n", size);
    free(buf);
    return 0;
}
