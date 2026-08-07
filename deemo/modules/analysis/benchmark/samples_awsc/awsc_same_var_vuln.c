/** awsc_same_var_vuln: OVERFLOW: write sz+128 > alloc sz */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char payload[8192];

void f(void) {
    volatile unsigned int sz = 256;
    char *buf = (char *)malloc(sz);
    if (!buf) return;
    memcpy(buf, payload, sz + 128);
    free(buf);
    printf("done\n");
}
int main(void) { memset(payload,'A',sizeof(payload)); f(); return 0; }
