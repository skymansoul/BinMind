/* CVE-2019-15846 — Exim TLS SNI heap overflow
 * Pattern: snprintf size computed from untrusted TLS extension length */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    unsigned host_len = 0x2000;  // long SNI hostname
    char *buf = (char *)malloc(256);
    if (buf) {
        snprintf(buf, host_len, "host: %s", "AAAA");  // host_len >> 256 → overflow
        printf("CVE-2019-15846: alloc=256 snprintf max=%u\n", host_len);
        free(buf);
    }
    return 0;
}
