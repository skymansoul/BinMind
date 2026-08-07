/**
 * sawce_arithmetic - malloc(x*4); memcpy(p, src, x*4) - same binop expression
 *
 * SAWCE test: alloc = count*4, write = count*4 -> same binop expression.
 * Expected: NO alert (structural equivalence of binop exprs).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char payload[512];

void sawce_arithmetic_vuln(void) {
    volatile unsigned int count = 32;
    char *buf = (char *)malloc(count * 4);
    if (!buf) return;
    /* Both alloc and write = count*4 -> structurally equivalent */
    memcpy(buf, payload, count * 4);
    printf("sawce_arithmetic: ok\n");
    free(buf);
}

int main(void) {
    memset(payload, 'A', sizeof(payload));
    sawce_arithmetic_vuln();
    return 0;
}
