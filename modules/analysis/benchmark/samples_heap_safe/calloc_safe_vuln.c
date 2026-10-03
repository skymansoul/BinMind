/** calloc_vuln: OVERFLOW: memcpy 128 > calloc 64 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile void *volatile_sink;
#define MK_BARRIER(x) __asm__ __volatile__("" : : "r"(x) : "memory")


int main() {
    void *p = calloc(64, 1);
    if (!p) return 1;
    volatile_sink = p;
    MK_BARRIER(0);
    char *src = malloc(128); memset(src,65,128); memcpy(p, src, 128); free(src);
    printf("calloc: vuln\n");
    return 0;
}
