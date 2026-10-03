/** awsc_calc_same_vuln: OVERFLOW: write len+1 > alloc len */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char payload[8192];

void f(int n) {
    size_t len = (size_t)n * 4;
    char *buf = (char *)malloc(len);
    if (!buf) return;
    memcpy(buf, payload, len + 1);
    free(buf);
    printf("done\n");
}
int main(void) { memset(payload,'A',sizeof(payload)); f(64); return 0; }
