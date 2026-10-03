/* CVE-2019-15794 — Linux kernel vhost/net heap overflow
 * Pattern: missing bounds check on desc->len before scatter-gather copy */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    unsigned alloc_sz = 256;
    unsigned desc_len = 0x2000;  // bogus descriptor length
    char *buf = (char *)malloc(alloc_sz);
    if (buf) {
        memset(buf, 0, alloc_sz);
        // BUG: desc_len > alloc_sz, no bounds check
        memcpy(buf, "DATA", desc_len > alloc_sz ? desc_len : 4);
        memset(buf, 0x41, desc_len);  // HEAP OVERFLOW
        printf("CVE-2019-15794: alloc=%u write=%u\n", alloc_sz, desc_len);
        free(buf);
    }
    return 0;
}
