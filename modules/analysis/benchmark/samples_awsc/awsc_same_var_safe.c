/** awsc_same_var_safe: SAFE: write sz == alloc sz (same variable) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char payload[8192];

void f(void) {
    volatile unsigned int sz = 256;
    char *buf = (char *)malloc(sz);
    if (!buf) return;
    memcpy(buf, payload, sz);
    free(buf);
    printf("done\n");
}
int main(void) { memset(payload,'A',sizeof(payload)); f(); return 0; }
