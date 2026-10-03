/* CWE-122: pointer offset + computed write length */
#include <stdlib.h>
#include <string.h>

void cwe122_offset(char *src, int offset, int len) {
    char *buf = (char *)malloc(128);
    if (buf) {
        memcpy(buf + offset, src, len);  /* offset+len may exceed 128 */
        free(buf);
    }
}

int main(void) {
    static char src[80];
    cwe122_offset(src, 32, 48);  /* 32+48=80 > 64 */
    return 0;
}
