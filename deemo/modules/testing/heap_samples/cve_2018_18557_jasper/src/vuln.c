/* CVE-2018-18557 — JasPer: declared length smaller than copied data */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct jp2_box { unsigned int declared_len; unsigned char *data; };
static struct jp2_box *parse_box(const unsigned char *raw, size_t raw_len) {
    struct jp2_box *b = (struct jp2_box *)malloc(sizeof(*b));
    if (!b) return NULL;
    b->declared_len = 0x40;             /* header-declared length */
    b->data = (unsigned char *)malloc(b->declared_len);
    if (!b->data) { free(b); return NULL; }
    memcpy(b->data, raw, raw_len);      /* BUG: raw_len > declared_len */
    return b;
}
int main(int argc, char **argv) {
    unsigned char payload[0x200];
    memset(payload, 'B', sizeof(payload));
    struct jp2_box *b = parse_box(payload, argc > 1 ? (size_t)atoi(argv[1]) : 0x100);
    if (b) { printf("[*] box len=%u\n", b->declared_len); free(b->data); free(b); }
    return 0;
}
