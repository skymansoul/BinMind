/* 守卫约束安全: if(n>256)n=256+malloc(n)+memcpy(n)
 * Has vulnerability: False
 */
#include <stdlib.h>
#include <string.h>
int guard_safe(int n) {
    if (n > 256) n = 256;
    char *buf = malloc(n);
    if (!buf) return -1;
    memcpy(buf, src, n);
    free(buf);
    return 0;
}
