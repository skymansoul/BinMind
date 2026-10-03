/** bounds_check_safe: SAFE: bounds check caps len */
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
    int len = 128; if (len > 128) return 1; char *src = malloc(len); memset(src,88,len); memcpy(p, src, len); free(src);
    printf("bounds_check: safe\n");
    return 0;
}
