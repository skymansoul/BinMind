/*
 * GAPSBV-STRESS-03: 仿射关系差分 — 测试dim1(AffineRelation).
 *
 * malloc(n*8+16) 后 memcpy(n*4) → diff = (n*8+16) - (n*4) = 4n+16 > 0 恒成立 → SAFE.
 * 另一种情况: malloc(n*4) 后 memcpy(n*8) → diff = 4n-8n = -4n < 0 对n>0成立 → OVERFLOW.
 * 关键: 仿射追踪必须识别共享变量n, 计算符号diff.
 * 此样本为SAFE变体(diff>0).
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv) {
    int n = (argc > 1) ? atoi(argv[1]) : 10;
    if (n <= 0 || n > 1000) return 1;
    /* alloc = n*8 + 16, write = n*4 */
    char *buf = (char *)malloc(n * 8 + 16);
    if (!buf) return 1;
    memcpy(buf, argv[1] ? argv[1] : "data", n * 4);
    free(buf);
    return 0;
}
