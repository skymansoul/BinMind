/** strncpy_safe: SAFE: strncpy 63 <= alloc 64 */
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
    char *src = malloc(63); memset(src,88,62); src[62]=0; strncpy((char*)p, src, 63); free(src);
    printf("strncpy: safe\n");
    return 0;
}
