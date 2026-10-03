/* realloc未扩展溢出: malloc(32)→realloc(32)+memcpy(64)
 * Has vulnerability: True
 */
#include <stdlib.h>
#include <string.h>
int realloc_overflow() {
    char *buf = malloc(32);
    if (!buf) return -1;
    buf = realloc(buf, 32);
    if (!buf) return -1;
    memcpy(buf, src, 64);
    free(buf);
    return 0;
}
