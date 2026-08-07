/**
 * sawce_derived_boundary - malloc(x); memcpy(p, src, x+1) - write is alloc+1, within padding
 *
 * SAWCE test: write size = alloc size + 1, within allocator padding.
 * Expected: NO alert (boundary safe within glibc 16-byte padding).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char payload[1024];

void sawce_derived_boundary_vuln(void) {
    volatile unsigned int sz = 128;
    char *buf = (char *)malloc(sz);
    if (!buf) return;
    /* write = sz + 1 = 129, alloc = 128, overflow=1 -> within padding */
    memcpy(buf, payload, sz + 1);
    printf("sawce_derived_boundary: boundary safe\n");
    free(buf);
}

int main(void) {
    memset(payload, 'A', sizeof(payload));
    sawce_derived_boundary_vuln();
    return 0;
}
