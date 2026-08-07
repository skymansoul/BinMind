/** double_bounds_safe: SAFE: capped len used for write */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile void *volatile_sink;
#define MK_BARRIER(x) __asm__ __volatile__("" : : "r"(x) : "memory")


int main() {
    void *p = malloc(512);
    if (!p) return 1;
    volatile_sink = p;
    MK_BARRIER(0);
    int len = 512; if (len < 0) return 1; if (len > 512) len = 512; char *src = malloc(len); memset(src,88,len); memcpy(p, src, len); free(src);
    printf("double_bounds: safe\n");
    return 0;
}
