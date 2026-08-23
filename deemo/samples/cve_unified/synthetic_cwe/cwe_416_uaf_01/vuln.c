/* CWE-416: Use-after-free �� not a heap overflow */
#include <stdlib.h>
#include <string.h>

void cwe416_uaf(char *src) {
    char *buf = (char *)malloc(64);
    free(buf);
    memcpy(buf, src, 64);  /* UAF �� differential from heap overflow */
}

int main(void) {
    static char src[64];
    cwe416_uaf(src);
    return 0;
}
