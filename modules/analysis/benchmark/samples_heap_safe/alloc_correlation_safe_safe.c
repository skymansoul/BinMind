/** alloc_correlation_safe: SAFE: same variable for alloc+write */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile void *volatile_sink;
#define MK_BARRIER(x) __asm__ __volatile__("" : : "r"(x) : "memory")


int main() {
    void *p = malloc(128);
    if (!p) return 1;
    volatile_sink = p;
    MK_BARRIER(0);
    int sz = 128; char *src = malloc(sz); memset(src,88,sz); memcpy(p, src, sz); free(src);
    printf("alloc_correlation: safe\n");
    return 0;
}
