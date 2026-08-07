/* calloc乘积溢出: calloc(8,16)+memcpy(192) — alloc=128, write=192 */
#include <stdlib.h>
#include <string.h>
void calloc_overflow() {
    char *buf = calloc(8, 16);
    if (!buf) return;
    memcpy(buf, src, 192);
    free(buf);
}
