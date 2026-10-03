/* 无共享变量: malloc(m)+memcpy(n) 无关系
 * Has vulnerability: False
 */
#include <stdlib.h>
#include <string.h>
int unrelated(int m, int n) {
    char *buf = malloc(m);
    if (!buf) return -1;
    if (n > m) {
        memcpy(buf, src, n);
    }
    free(buf);
    return 0;
}
