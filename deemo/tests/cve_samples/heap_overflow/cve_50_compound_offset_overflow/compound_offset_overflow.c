#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * CVE-50: 复合算术偏移溢出 — 复合表达式导致偏移超出缓冲区
 *
 * 模式: malloc(64);
 *       if (base > 32) base = 32;
 *       if (stride > 4) stride = 4;
 *       off = base * stride;  // max = 32*4 = 128
 *       memcpy(buf + off, src, 8);  // write_end = 128+8 = 136 > usable(64)=72 → OVERFLOW
 */
int main(int argc, char **argv) {
    int base = 16, stride = 2;
    if (argc > 1) base = atoi(argv[1]);
    if (argc > 2) stride = atoi(argv[2]);

    if (base > 32) base = 32;
    if (stride > 4) stride = 4;

    char *buf = (char *)malloc(64);
    if (!buf) return 1;

    int off = base * stride;
    char src[16];
    memset(src, 'G', 16);
    memcpy(buf + off, src, 8);

    printf("compound_offset_overflow: off=%d\n", off);
    free(buf);
    return 0;
}
