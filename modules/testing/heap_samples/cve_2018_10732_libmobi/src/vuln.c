/* CVE-2018-10732 — libmobi parse_huff: header-driven memcpy overflow */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void *parse_huff(unsigned int hdr_len, const unsigned char *data) {
    void *buf = malloc(0x40);           /* fixed small buffer */
    if (!buf) return NULL;
    memcpy(buf, data, hdr_len);         /* BUG: hdr_len from untrusted header */
    return buf;
}
int main(int argc, char **argv) {
    unsigned int len = argc > 1 ? (unsigned int)atoi(argv[1]) : 0x100;
    unsigned char payload[0x200];
    memset(payload, 'A', sizeof(payload));
    void *p = parse_huff(len, payload);
    if (p) { printf("[*] parsed %u bytes\n", len); free(p); }
    return 0;
}
