/** align_safe_safe: SAFE: memcpy 62 <= malloc 62 (glibc align) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile void *volatile_sink;
#define MK_BARRIER(x) __asm__ __volatile__("" : : "r"(x) : "memory")


int main() {
    void *p = malloc(62);
    if (!p) return 1;
    volatile_sink = p;
    MK_BARRIER(0);
    char *src = (char*)malloc(256);
    memset(src, 'A', 62);
    memcpy(p, src, 62);
    free(src);
    printf("align_safe: safe\n");
    return 0;
}
