/*
 * GAPSBV-STRESS-05: Loop累加溢出 — 测试dim6(LoopAccumulation).
 *
 * for循环中 i*256 逐步累加写入, malloc(n*256)后memcpy n*256.
 * alloc=n*256, copy=n*256 → 精确相等, diff=0.
 * 若循环内逐次写入, 总写入量≤alloc → SAFE.
 * 期望: SAFE (dim6 loop_accumulate证明精确匹配)
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv) {
    int n = (argc > 1) ? atoi(argv[1]) : 4;
    if (n <= 0 || n > 100) return 1;
    size_t chunk = 256;
    char *buf = (char *)malloc(n * chunk);
    if (!buf) return 1;
    for (int i = 0; i < n; i++) {
        memcpy(buf + i * chunk, argv[1] ? argv[1] : "loop_data", chunk);
    }
    free(buf);
    return 0;
}
