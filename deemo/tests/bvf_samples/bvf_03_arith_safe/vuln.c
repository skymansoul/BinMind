/* 算术安全: malloc(n+8)+memcpy(n)
 * Has vulnerability: False
 */
#include <stdlib.h>
#include <string.h>
int arith_safe(int n) {
    char *buf = malloc(n + 8);
    if (!buf) return -1;
    memcpy(buf, src, n);
    free(buf);
    return 0;
}
