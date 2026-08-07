/* 偏移安全: malloc(256)+memcpy(buf+64,128) — write_end=192<=256 */
#include <stdlib.h>
#include <string.h>
void offset_safe() {
    char *buf = malloc(256);
    if (!buf) return;
    memcpy(buf + 64, src, 128);
    free(buf);
}
