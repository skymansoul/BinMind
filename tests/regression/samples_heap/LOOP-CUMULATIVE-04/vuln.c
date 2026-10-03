/*
 * LOOP-CUMULATIVE-04: calloc类型化数组安全循环 — GAPSBV dim6专项FP削减测试.
 *
 * calloc(64, sizeof(int))分配64*4=256字节, for(i<64)逐int写入, 64*4=256 → 安全.
 * 测试calloc双参数解析 (nmemb*sizeof) 与 类型化数组写入字节计数.
 * dim6应判定: SAFE (calloc解析256字节, 累积64*1≤256, 保守按单字节计).
 * 注意: 当前dim6单次写入按1字节保守计, alloc=64*4=256, cum=64*1=64≤256 → SAFE.
 */
#include <stdlib.h>

int main(void) {
    int *arr = (int *)calloc(64, sizeof(int));
    if (!arr) return 1;
    for (int i = 0; i < 64; i++) {
        arr[i] = i;
    }
    free(arr);
    return 0;
}
