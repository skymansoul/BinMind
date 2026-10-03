/* 变量常数差溢出: malloc(n)+memcpy(n+8) — write比alloc多8字节 */
#include <stdlib.h>
#include <string.h>
void const_diff_overflow(int n) {
    char *buf = malloc(n);
    if (!buf) return;
    memcpy(buf, src, n + 8);
    free(buf);
}
