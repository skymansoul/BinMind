/** bounds_check_vuln: OVERFLOW: len+128 bypasses check */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile void *volatile_sink;
#define MK_BARRIER(x) __asm__ __volatile__("" : : "r"(x) : "memory")


int main() {
    void *p = malloc(256);
    if (!p) return 1;
    volatile_sink = p;
    MK_BARRIER(0);
    int len = 256; if (len > 256) return 1; char *src = malloc(len+128); memset(src,88,len+128); memcpy(p, src, len+128); free(src);
    printf("bounds_check: vuln\n");
    return 0;
}
