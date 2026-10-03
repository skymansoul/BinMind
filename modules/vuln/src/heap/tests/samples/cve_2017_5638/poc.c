/* CVE-2017-5638 — Apache Struts2 Jakarta Multipart parser RCE
 * Pattern: Content-Type header length → malloc → overflow via boundary scan
 * Minimized: controlled_size → malloc → memcpy with larger computed size */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned g_size = 256;
int main(void) {
    unsigned alloc_sz = g_size;
    char *buf = (char *)malloc(alloc_sz);
    if (buf) {
        unsigned actual = g_size + 0x1000;  // boundary exceeds buffer
        memset(buf, 0x41, actual);  // HEAP OVERFLOW
        printf("CVE-2017-5638: %u alloc, %u write\n", alloc_sz, actual);
        free(buf);
    }
    return 0;
}
