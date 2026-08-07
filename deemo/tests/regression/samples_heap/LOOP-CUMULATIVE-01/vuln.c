/*
 * LOOP-CUMULATIVE-01: 单行for循环溢出 — GAPSBV dim6专项测试.
 *
 * malloc(64)分配64字节, for(i<100)逐字节写入buf[i], 累积100字节 > 64 → 溢出.
 * 模式: 单行循环体 for(...) { stmt; } — 测试_find_body_end单行体修复.
 * dim6应判定: OVERFLOW (loop cum 1*100=100 > 64).
 */
#include <stdlib.h>

int main(void) {
    char *buf = (char *)malloc(64);
    if (!buf) return 1;
    for (int i = 0; i < 100; i++) { buf[i] = 'A'; }
    free(buf);
    return 0;
}
