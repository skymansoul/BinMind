/* 变量常数差安全: malloc(n+16)+memcpy(n) — alloc比write多16字节余量 */
#include <stdlib.h>
#include <string.h>
void const_diff_safe(int n) {
    char *buf = malloc(n + 16);
    if (!buf) return;
    memcpy(buf, src, n);
    free(buf);
}
