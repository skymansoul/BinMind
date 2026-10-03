/* 偏移溢出: malloc(256)+memcpy(buf+200,128) — write_end=328>256 */
#include <stdlib.h>
#include <string.h>
void offset_overflow() {
    char *buf = malloc(256);
    if (!buf) return;
    memcpy(buf + 200, src, 128);
    free(buf);
}
