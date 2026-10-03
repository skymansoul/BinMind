/** awsc_off_by_k_vuln: OVERFLOW: write sz+32 > usable */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char payload[8192];

void f(void) {
    volatile unsigned int sz = 62;
    char *buf = (char *)malloc(sz);
    if (!buf) return;
    memcpy(buf, payload, sz + 32);
    free(buf);
    printf("done\n");
}
int main(void) { memset(payload,'A',sizeof(payload)); f(); return 0; }
