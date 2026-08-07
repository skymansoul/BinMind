/** constant_prop_vuln: OVERFLOW: variable write size 512 > 256 */
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
    enum { BUFSZ = 256 }; char *src = malloc(512); memset(src,65,512); int ws = 512; memcpy(p, src, ws); free(src);
    printf("constant_prop: vuln\n");
    return 0;
}
