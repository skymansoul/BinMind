/* CWE-122: loop write with dynamic bound */
#include <stdlib.h>

void cwe122_loop(char *src, int count) {
    char *buf = (char *)malloc(64);
    if (buf) {
        for (int i = 0; i < count; i++) {
            buf[i] = src[i];  /* count may exceed 64 �� OVERFLOW */
        }
        free(buf);
    }
}

int main(void) {
    static char src[128];
    cwe122_loop(src, 100);  /* 100 > 64 */
    return 0;
}
