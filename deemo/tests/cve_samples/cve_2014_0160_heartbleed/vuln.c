/* CVE-2014-0160 Heartbleed — heap over-read via TLS heartbeat / CWE-126 */
#include <stdlib.h>
#include <string.h>
typedef struct { int length; char payload[65535]; } hb_t;
void heartbeat(hb_t *hb, unsigned char *resp) {
    if (hb->length < 0) return;
    memcpy(resp, hb->payload, hb->length); /* BUG: length not upper-bounded */
}
int main(void) {
    hb_t *h = malloc(sizeof(hb_t)); unsigned char *r = malloc(65535);
    h->length = 65535+100; memset(h->payload,'A',16);
    heartbeat(h, r); free(h); free(r); return 0;
}
