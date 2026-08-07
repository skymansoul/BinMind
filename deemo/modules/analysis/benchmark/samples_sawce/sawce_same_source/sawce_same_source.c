/**
 * sawce_same_source - malloc(x); memcpy(p, src, x) - same variable for alloc and write size
 *
 * SAWCE test: alloc and write size come from the same variable.
 * Expected: NO alert (SAWCE should prove structural equivalence).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char payload[1024];

void sawce_same_source_vuln(void) {
    /* Volatile to prevent constant folding */
    volatile unsigned int sz = 128;
    char *buf = (char *)malloc(sz);
    if (!buf) return;
    /* alloc size == write size (both = sz) -> SAFE by SAWCE */
    memcpy(buf, payload, sz);
    printf("sawce_same_source: ok\n");
    free(buf);
}

/* Different source: should alert */
void sawce_same_source_diff(void) {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    volatile unsigned int wlen = 128;
    memcpy(buf, payload, wlen);  /* 128 > 64 -> OVERFLOW */
    printf("sawce_same_source_diff: overflow\n");
    free(buf);
}

int main(void) {
    memset(payload, 'A', sizeof(payload));
    sawce_same_source_vuln();
    sawce_same_source_diff();
    return 0;
}
