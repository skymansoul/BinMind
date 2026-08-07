/* 共享变量安全: malloc(n)+memcpy(n)
 * Has vulnerability: False
 */
#include <stdlib.h>
#include <string.h>
int safe_copy(int n) {
    char *buf = malloc(n);
    if (!buf) return -1;
    memcpy(buf, src, n);
    free(buf);
    return 0;
}
