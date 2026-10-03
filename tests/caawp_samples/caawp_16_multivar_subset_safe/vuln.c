/* 多变量子集安全: malloc(n+m)+memcpy(n) — write是alloc的子集 */
#include <stdlib.h>
#include <string.h>
void multivar_safe(int n, int m) {
    char *buf = malloc(n + m);
    if (!buf) return;
    memcpy(buf, src, n);
    free(buf);
}
