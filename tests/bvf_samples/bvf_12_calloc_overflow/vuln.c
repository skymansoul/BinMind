/* calloc溢出: calloc(n,4)+memcpy(n*8)
 * Has vulnerability: True
 */
#include <stdlib.h>
#include <string.h>
int calloc_overflow(int n) {
    char *buf = calloc(n, 4);
    if (!buf) return -1;
    memcpy(buf, src, n * 8);
    free(buf);
    return 0;
}
