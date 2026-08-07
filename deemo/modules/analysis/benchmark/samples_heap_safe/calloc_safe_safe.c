/** calloc_safe: SAFE: memcpy 64 = calloc 64 */
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
    char *src = malloc(64); memset(src,88,64); memcpy(p, src, 64); free(src);
    printf("calloc: safe\n");
    return 0;
}
