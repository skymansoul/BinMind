/* calloc安全: calloc(n,4)+memcpy(n*4)
 * Has vulnerability: False
 */
#include <stdlib.h>
#include <string.h>
int calloc_safe(int n) {
    char *buf = calloc(n, 4);
    if (!buf) return -1;
    memcpy(buf, src, n * 4);
    free(buf);
    return 0;
}
