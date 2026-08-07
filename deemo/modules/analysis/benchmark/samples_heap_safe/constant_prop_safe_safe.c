/** constant_prop_safe: SAFE: constant 128 <= BUFSZ 256 */
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
    enum { BUFSZ = 256 }; char *src = malloc(128); memset(src,88,128); memcpy(p, src, 128); free(src);
    printf("constant_prop: safe\n");
    return 0;
}
