#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

void *safe_alloc(size_t nmemb, size_t size) {
    if (nmemb > 0 && size > SIZE_MAX / nmemb) {
        return NULL;  /* SAFE: overflow check */
    }
    return calloc(nmemb, size);
}

int main(void) {
    size_t n = 100;
    int *buf = (int *)safe_alloc(n, sizeof(int));
    if (!buf) { printf("alloc failed\n"); return 1; }
    for (size_t i = 0; i < n; i++) buf[i] = (int)i;
    printf("safe bounds: buf[99] = %d\n", buf[99]);
    free(buf);
    return 0;
}
