/* loop writes beyond allocated buffer via index increment */
#include <stdlib.h>

void edge_loop_overflow(char *src) {
    char *buf = (char *)malloc(64);
    if (buf) {
        for (int i = 0; i < 128; i++) {
            buf[i] = src[i];  /* i reaches 127, buffer only 64 �� OVERFLOW */
        }
        free(buf);
    }
}

int main(void) {
    static char src[200];
    edge_loop_overflow(src);  /* loop writes 0..127 into 64-byte buf */
    return 0;
}
