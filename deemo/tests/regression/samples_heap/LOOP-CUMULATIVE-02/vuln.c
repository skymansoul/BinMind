/*
 * LOOP-CUMULATIVE-02: 多行安全循环 — GAPSBV dim6专项FP削减测试.
 *
 * malloc(100)分配100字节, for(i<100)逐字节写入, 累积100字节=100 → 安全.
 * 无dim6时管道可能因memcpy/array_store模式误报, dim6应判定SAFE.
 * dim6应判定: SAFE (loop cum 1*100=100 <= 100).
 */
#include <stdlib.h>

int main(void) {
    char *buf = (char *)malloc(100);
    if (!buf) return 1;
    for (int i = 0; i < 100; i++) {
        buf[i] = (char)(i & 0xff);
    }
    free(buf);
    return 0;
}
