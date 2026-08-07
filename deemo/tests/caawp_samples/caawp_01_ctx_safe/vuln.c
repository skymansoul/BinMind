/* 上下文安全: malloc(256)+helper(buf,128) — 同一helper不同调用点安全 */
#include <stdlib.h>
#include <string.h>
void helper(char *dst, int sz) {
    memcpy(dst, src, sz);
}
void ctx_safe() {
    char *buf = malloc(256);
    if (!buf) return;
    helper(buf, 128);
    free(buf);
}
