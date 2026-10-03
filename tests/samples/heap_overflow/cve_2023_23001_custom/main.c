/* CVE-2023-23001-like: custom heap overflow in network buffer handling */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct pkt { int len; char payload[64]; };
int main(void) {
    struct pkt *p = malloc(sizeof(*p));
    if (!p) return 1;
    p->len = 256;
    memset(p->payload, 'P', 256);  /* overflow: payload is only 64 bytes */
    free(p);
    return 0;
}
