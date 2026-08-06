/* CVE-2019-15291 — Linux USB core UAF via malformed descriptor / CWE-416 */
#include <stdlib.h>
typedef struct { int id; char *desc; } usb_dev_t;
static usb_dev_t *g_dev = NULL;
void usb_disconnect(void) { free(g_dev->desc); free(g_dev); /* g_dev dangling */ }
void usb_probe(void) {
    g_dev = malloc(sizeof(usb_dev_t)); g_dev->desc = malloc(64);
    usb_disconnect();
    g_dev->desc[0] = 'X'; /* UAF */
}
int main(void) { usb_probe(); return 0; }
