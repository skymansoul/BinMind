/* CVE-2023-38545 — libcurl SOCKS5 heap overflow
 * Pattern: slow negotiation → small buffer → large hostname overflows */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    unsigned hostname_len = 0x10000;  // 64KB hostname
    unsigned alloc = 256;             // initial small buffer
    char *buf = (char *)malloc(alloc);
    if (buf) {
        memset(buf, 0x41, hostname_len);  // HEAP OVERFLOW
        printf("CVE-2023-38545: alloc=%u write=%u\n", alloc, hostname_len);
        free(buf);
    }
    return 0;
}
