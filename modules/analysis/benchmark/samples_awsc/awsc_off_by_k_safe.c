/** awsc_off_by_k_safe: SAFE: write sz+8 within glibc padding */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char payload[8192];

void f(void) {
    volatile unsigned int sz = 62;
    char *buf = (char *)malloc(sz);
    if (!buf) return;
    memcpy(buf, payload, sz + 8);
    free(buf);
    printf("done\n");
}
int main(void) { memset(payload,'A',sizeof(payload)); f(); return 0; }
