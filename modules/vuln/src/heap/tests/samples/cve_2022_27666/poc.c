/* CVE-2022-27666 — Linux kernel IPsec ESP output overflow
 * Pattern: scatter-gather list with variable fragment sizes → computed alloc insufficient */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    unsigned hdr_len = 20;
    unsigned payload_len = 0x1000;
    unsigned alloc = hdr_len + payload_len + 16;  // includes padding estimate
    char *buf = (char *)malloc(alloc);
    if (buf) {
        unsigned actual = hdr_len + payload_len + 64;  // actual padding > estimated
        memset(buf, 0x41, actual);  // HEAP OVERFLOW
        printf("CVE-2022-27666: alloc=%u write=%u\n", alloc, actual);
        free(buf);
    }
    return 0;
}
