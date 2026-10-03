/** realloc_safe: SAFE: realloc size tracked */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile void *volatile_sink;
#define MK_BARRIER(x) __asm__ __volatile__("" : : "r"(x) : "memory")


int main() {
    void *p = malloc(64);
    if (!p) return 1;
    volatile_sink = p;
    MK_BARRIER(0);
    void *q = realloc(p, 128); if (q) p = q; char *src = malloc(120); memset(src,88,120); memcpy(p, src, 120); free(src);
    printf("realloc: safe\n");
    return 0;
}
