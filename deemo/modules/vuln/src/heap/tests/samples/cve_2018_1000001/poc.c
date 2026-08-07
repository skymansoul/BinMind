/* CVE-2018-1000001 — catdoc xls2csv heap overflow
 * Pattern: user-controlled size → malloc → memcpy with larger computed offset */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned g_user_len = 64;
int main(void) {
    unsigned alloc_sz = g_user_len + 16;  // header + body
    char *buf = (char *)malloc(alloc_sz);
    if (buf) {
        unsigned copy_sz = g_user_len + 256;  // bad computation: adds too much
        memset(buf, 0x41, copy_sz);  // HEAP OVERFLOW: writes 256 extra bytes
        printf("CVE-2018-1000001: alloc=%u write=%u\n", alloc_sz, copy_sz);
        free(buf);
    }
    return 0;
}
