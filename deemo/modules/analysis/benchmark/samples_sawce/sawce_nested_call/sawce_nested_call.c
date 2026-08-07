/**
 * sawce_nested_call - malloc(get_size()); memcpy(p, src, get_size()) - same call-ret source
 *
 * SAWCE test: alloc and write size both come from same function return.
 * Expected: NO alert (same call-ret base node).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char payload[256];

static unsigned int get_size(void) {
    return 128;
}

void sawce_nested_call_vuln(void) {
    char *buf = (char *)malloc(get_size());
    if (!buf) return;
    /* Both alloc and write use get_size() return -> same call-ret expr */
    memcpy(buf, payload, get_size());
    printf("sawce_nested_call: ok\n");
    free(buf);
}

int main(void) {
    memset(payload, 'A', sizeof(payload));
    sawce_nested_call_vuln();
    return 0;
}
