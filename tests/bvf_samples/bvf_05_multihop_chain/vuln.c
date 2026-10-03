/* 多跳赋值链: n→sz→alloc, n→tmp→write
 * Has vulnerability: False
 */
#include <stdlib.h>
#include <string.h>
int multihop(int n) {
    int sz = n;
    char *buf = malloc(sz);
    if (!buf) return -1;
    int tmp = n;
    memcpy(buf, src, tmp);
    free(buf);
    return 0;
}
