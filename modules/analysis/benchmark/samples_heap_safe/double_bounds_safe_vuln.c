/** double_bounds_vuln: OVERFLOW: write uses uncapped value */
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
    int len = 1024; if (len < 0) return 1; if (len > 512) len = 512; char *src = malloc(1024); memset(src,88,1024); memcpy(p, src, 1024); free(src);
    printf("double_bounds: vuln\n");
    return 0;
}
