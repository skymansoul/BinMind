/* realloc缩小后溢出: malloc(256)→realloc(64)+memcpy(128) */
#include <stdlib.h>
#include <string.h>
void realloc_shrink_overflow() {
    char *buf = malloc(256);
    if (!buf) return;
    buf = realloc(buf, 64);
    if (!buf) return;
    memcpy(buf, src, 128);
    free(buf);
}
