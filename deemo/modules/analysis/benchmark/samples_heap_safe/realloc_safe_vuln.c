/** realloc_vuln: OVERFLOW: 256 > realloc 128 */
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
    void *q = realloc(p, 128); if (q) p = q; char *src = malloc(256); memset(src,65,256); memcpy(p, src, 256); free(src);
    printf("realloc: vuln\n");
    return 0;
}
