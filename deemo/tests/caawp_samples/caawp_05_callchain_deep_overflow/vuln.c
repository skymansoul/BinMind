/* 深调用链溢出: main→middle(64)→inner(256) — 两层调用, 参数传递溢出 */
#include <stdlib.h>
#include <string.h>
void inner(char *dst, int sz) {
    memcpy(dst, src, sz);
}
void middle(char *buf, int sz) {
    inner(buf, sz);
}
void callchain_overflow() {
    char *buf = malloc(64);
    if (!buf) return;
    middle(buf, 256);
    free(buf);
}
