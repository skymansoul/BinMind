#include <stdio.h>
#include <stdlib.h>

size_t compute_size(int n) {
    /* OVERFLOW: n*sizeof(int) wraps for large n */
    return (size_t)(n * (int)sizeof(int));
}

int main(void) {
    int n = 0x40000001;
    size_t sz = compute_size(n);
    int *buf = (int *)malloc(sz);
    if (!buf) { printf("alloc failed\n"); return 1; }
    /* sz=4, but n=0x40000001 → heap overflow */
    buf[n-1] = 42;
    printf("cross-func overflow: sz=%zu, buf[%d]=%d\n", sz, n-1, buf[n-1]);
    free(buf);
    return 0;
}
