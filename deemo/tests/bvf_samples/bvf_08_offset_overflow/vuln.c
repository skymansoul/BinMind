/* 偏移溢出: malloc(64)+memcpy(buf+48,32)
 * Has vulnerability: True
 */
#include <stdlib.h>
#include <string.h>
int offset_overflow() {
    char *buf = malloc(64);
    if (!buf) return -1;
    memcpy(buf + 48, src, 32);
    free(buf);
    return 0;
}
