/* 偏移安全: malloc(128)+memcpy(buf+64,64)
 * Has vulnerability: False
 */
#include <stdlib.h>
#include <string.h>
int offset_safe() {
    char *buf = malloc(128);
    if (!buf) return -1;
    memcpy(buf + 64, src, 64);
    free(buf);
    return 0;
}
