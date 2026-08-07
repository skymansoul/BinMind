/* 共享变量溢出: malloc(n)+memcpy(n*2)
 * Has vulnerability: True
 */
#include <stdlib.h>
#include <string.h>
int overflow_copy(int n) {
    char *buf = malloc(n);
    if (!buf) return -1;
    memcpy(buf, src, n * 2);
    free(buf);
    return 0;
}
