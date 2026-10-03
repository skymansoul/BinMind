/* 上下文溢出: malloc(64)+helper(buf,256) — 同一helper不同调用点溢出 */
#include <stdlib.h>
#include <string.h>
void helper(char *dst, int sz) {
    memcpy(dst, src, sz);
}
void ctx_overflow() {
    char *buf = malloc(64);
    if (!buf) return;
    helper(buf, 256);
    free(buf);
}
