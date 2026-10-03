#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    /* nelem * sizeof(int) = 0x40000001 * 4 = 4 (overflow truncated) */
    size_t nelem = 0x40000001;
    size_t alloc_size = nelem * sizeof(int);
    int *buf = (int *)malloc(alloc_size);
    if (!buf) { printf("alloc failed\n"); return 1; }
    /* OVERFLOW: allocated only 4 bytes, but loop expects 0x40000001*4 */
    for (size_t i = 0; i < nelem; i++) {
        buf[i] = (int)i;  /* heap overflow at i >= 1 */
    }
    printf("overflow complete\n");
    free(buf);
    return 0;
}
