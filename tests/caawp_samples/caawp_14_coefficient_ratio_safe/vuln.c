/* 系数比安全: malloc(n*4)+memcpy(n) — alloc_coef>write_coef */
#include <stdlib.h>
#include <string.h>
void coef_safe(int n) {
    char *buf = malloc(n * 4);
    if (!buf) return;
    memcpy(buf, src, n);
    free(buf);
}
