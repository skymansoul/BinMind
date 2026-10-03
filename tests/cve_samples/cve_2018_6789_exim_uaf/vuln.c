/* CVE-2018-6789 — Exim MTA base64 decode UAF / CWE-416 */
#include <stdlib.h>
#include <string.h>
void decode_base64(char *in, int len) {
    char *buf = malloc(len); memcpy(buf, in, len);
    free(buf);
    /* BUG: buf used after free if len triggers realloc path */
    if (len > 64) buf[0] = 'X';
}
int main(void) { char d[128]; memset(d,'A',128); decode_base64(d,128); return 0; }
