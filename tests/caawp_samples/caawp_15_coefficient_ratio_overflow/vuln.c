/* 系数比溢出: malloc(n)+memcpy(n*2) — write_coef>alloc_coef */
#include <stdlib.h>
#include <string.h>
void coef_overflow(int n) {
    char *buf = malloc(n);
    if (!buf) return;
    memcpy(buf, src, n * 2);
    free(buf);
}
