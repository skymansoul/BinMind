/* CVE-2019-18604 ¡ª gnuplot PDF: alloc per xref_len, copy per data_len */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct pdf_xref { unsigned int xref_len; unsigned int data_len; };
static void *parse_xref(const struct pdf_xref *x, const void *data) {
    void *buf = malloc(x->xref_len);    /* alloc from xref_len */
    if (!buf) return NULL;
    memcpy(buf, data, x->data_len);     /* BUG: data_len independent */
    return buf;
}
int main(int argc, char **argv) {
    struct pdf_xref x;
    x.xref_len = argc > 1 ? (unsigned int)atoi(argv[1]) : 0x10;
    x.data_len = 0x100;                 /* crafted header: data_len large */
    unsigned char payload[0x200];
    memset(payload, 'D', sizeof(payload));
    void *p = parse_xref(&x, payload);
    if (p) { printf("[*] xref %u\n", x.xref_len); free(p); }
    return 0;
}
