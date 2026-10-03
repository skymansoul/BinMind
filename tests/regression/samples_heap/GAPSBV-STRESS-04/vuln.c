/*
 * GAPSBV-STRESS-04: 仿射关系溢出 — 测试dim1(AffineRelation) OVERFLOW判定.
 *
 * malloc(n*4) 后 memcpy(n*8) → diff = 4n-8n = -4n < 0 → OVERFLOW.
 * 对比STRESS-03(SAFE), 这是真正的溢出.
 * 期望: OVERFLOW
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv) {
    int n = (argc > 1) ? atoi(argv[1]) : 10;
    if (n <= 0 || n > 1000) return 1;
    /* alloc = n*4, write = n*8 → 溢出 */
    char *buf = (char *)malloc(n * 4);
    if (!buf) return 1;
    memcpy(buf, argv[1] ? argv[1] : "overflow_data", n * 8);
    free(buf);
    return 0;
}
