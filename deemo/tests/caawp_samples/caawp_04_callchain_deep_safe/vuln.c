/* 深调用链安全: main→middle(256)→inner(128) — 两层调用, 参数传递安全 */
#include <stdlib.h>
#include <string.h>
void inner(char *dst, int sz) {
    memcpy(dst, src, sz);
}
void middle(char *buf, int sz) {
    inner(buf, sz);
}
void callchain_safe() {
    char *buf = malloc(256);
    if (!buf) return;
    middle(buf, 128);
    free(buf);
}
