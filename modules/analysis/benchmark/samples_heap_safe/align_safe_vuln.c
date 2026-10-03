/** align_safe_vuln: OVERFLOW: memcpy 80 > malloc 62 usable 72 */
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
    memset(src, 'A', 80);
    memcpy(p, src, 80);
    free(src);
    printf("align_safe: vuln\n");
    return 0;
}
