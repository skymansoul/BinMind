#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    size_t n = 0x10000001;
    size_t sz = 4;
    /* calloc(n, sz) → n*sz wraps to 4 bytes */
    int *buf = (int *)calloc(n, sz);
    if (!buf) { printf("calloc failed\n"); return 1; }
    /* OVERFLOW: expects n*4 bytes, got only 4 */
    buf[0] = 42;
    buf[n-1] = 99;  /* writes far past allocated region */
    printf("calloc overflow: buf[%zu] = %d\n", n-1, buf[n-1]);
    free(buf);
    return 0;
}
