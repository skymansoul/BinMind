/* realloc扩展安全: malloc(32)→realloc(128)+memcpy(64)
 * Has vulnerability: False
 */
#include <stdlib.h>
#include <string.h>
int realloc_safe() {
    char *buf = malloc(32);
    if (!buf) return -1;
    buf = realloc(buf, 128);
    if (!buf) return -1;
    memcpy(buf, src, 64);
    free(buf);
    return 0;
}
