/* CWE-415: Double free */
#include <stdlib.h>
#include <string.h>

void cwe415_double_free(char *src) {
    char *buf = (char *)malloc(64);
    if (buf) {
        memcpy(buf, src, 64);
        free(buf);
        free(buf);  /* double free �� not heap overflow */
    }
}

int main(void) {
    static char src[64];
    cwe415_double_free(src);
    return 0;
}
