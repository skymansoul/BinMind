/* calloc with wrong element count */
#include <stdlib.h>
#include <string.h>

void edge_calloc_mismatch(char *src) {
    int count = 16;
    int *buf = (int *)calloc(count, sizeof(int));  /* 16*4=64 bytes */
    if (buf) {
        memcpy(buf, src, 128);  /* 128 > 64 �� OVERFLOW */
        free(buf);
    }
}

int main(void) {
    static char src[200];
    edge_calloc_mismatch(src);  /* memcpy 128 > 64 */
    return 0;
}
