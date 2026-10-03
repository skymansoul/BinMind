/* CVE-2023-2002 — Linux Bluetooth L2CAP UAF / CWE-416 */
#include <stdlib.h>
#include <string.h>
typedef struct { int cid; char *buf; } l2cap_chan_t;
l2cap_chan_t *g_chan = NULL;
void l2cap_close(void) { free(g_chan->buf); free(g_chan); }
void l2cap_data(char *d, int len) {
    if (!g_chan) { g_chan = malloc(sizeof(l2cap_chan_t)); g_chan->buf = malloc(256); }
    l2cap_close();
    memcpy(g_chan->buf, d, len); /* UAF: g_chan->buf freed */
}
int main(void) { l2cap_data("AAAA", 4); return 0; }
