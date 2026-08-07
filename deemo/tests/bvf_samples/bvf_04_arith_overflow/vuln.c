/* 算术溢出: malloc(n)+memcpy(n+128)
 * Has vulnerability: True
 */
#include <stdlib.h>
#include <string.h>
int arith_overflow(int n) {
    char *buf = malloc(n);
    if (!buf) return -1;
    memcpy(buf, src, n + 128);
    free(buf);
    return 0;
}
