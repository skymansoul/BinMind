/** strncpy_vuln: OVERFLOW: strncpy 128 > alloc 64 */
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
    char *src = malloc(128); memset(src,65,127); src[127]=0; strncpy((char*)p, src, 128); free(src);
    printf("strncpy: vuln\n");
    return 0;
}
