/** loop_accumulate_vuln: OVERFLOW: 5*64=320 > alloc 256 */
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
    char *src = malloc(256); memset(src,65,256); for (int i=0; i<5; i++) memcpy((char*)p+i*64, src, 64); free(src);
    printf("loop_accumulate: vuln\n");
    return 0;
}
