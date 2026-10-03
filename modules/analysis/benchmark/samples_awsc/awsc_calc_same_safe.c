/** awsc_calc_same_safe: SAFE: write len == alloc len (calc) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char payload[8192];

void f(int n) {
    size_t len = (size_t)n * 4;
    char *buf = (char *)malloc(len);
    if (!buf) return;
    memcpy(buf, payload, len);
    free(buf);
    printf("done\n");
}
int main(void) { memset(payload,'A',sizeof(payload)); f(64); return 0; }
