/* calloc乘积安全: calloc(8,32)+memcpy(128) — alloc=256, write=128 */
#include <stdlib.h>
#include <string.h>
void calloc_safe() {
    char *buf = calloc(8, 32);
    if (!buf) return;
    memcpy(buf, src, 128);
    free(buf);
}
