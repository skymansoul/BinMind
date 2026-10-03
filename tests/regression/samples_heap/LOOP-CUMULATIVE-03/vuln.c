/*
 * LOOP-CUMULATIVE-03: off-by-one循环界溢出 — GAPSBV dim6专项测试.
 *
 * malloc(32)分配32字节, for(i<=32)写入buf[0..32]共33字节 → off-by-one溢出.
 * 循环条件 i<=32 而非 i<32, 导致多写1字节.
 * dim6应判定: OVERFLOW (loop cum 1*33=33 > 32).
 *
 * CWE-193: Off-by-one Error.
 */
#include <stdlib.h>

int main(void) {
    char *buf = (char *)malloc(32);
    if (!buf) return 1;
    for (int i = 0; i <= 32; i++) {
        buf[i] = (char)i;
    }
    free(buf);
    return 0;
}
