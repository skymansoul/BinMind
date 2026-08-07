/*
 * FP-15: 堆溢出通过循环累积
 *
 * for(i=0; i<=32; i++) buf[i] = ...;
 * buf=malloc(32), 循环写到 i=32 (共 33 字节) → 溢出 1 字节。
 * 循环边界分析应检测到 i<=32 > 分配大小 32。
 */
#include <stdlib.h>
#include <stdio.h>

int main(void) {
    char *buf = malloc(32);
    if (!buf) return 1;
    // 循环写到 buf[32], 即第 33 个字节 → off-by-one 溢出
    for (int i = 0; i <= 32; i++) {
        buf[i] = (char)(i & 0xff);
    }
    printf("off-by-one: buf[31]=%d buf[32] overflowed\n", buf[31]);
    free(buf);
    return 0;
}
