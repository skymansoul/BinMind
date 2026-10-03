/** alloc_correlation_vuln: OVERFLOW: sz modified after alloc */
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
    int sz = 128; char *src = malloc(256); memset(src,65,256); sz = 16; memcpy(p, src, 256); free(src);
    printf("alloc_correlation: vuln\n");
    return 0;
}
