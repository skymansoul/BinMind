/* malloc(64) + memcpy(buf+32, src, 48) = writes buf[32..79], overflows at 64 */
#include <stdlib.h>
#include <string.h>

void edge_offset_overflow(char *src) {
    char *buf = (char *)malloc(64);
    if (buf) {
        memcpy(buf + 32, src, 48);  /* 32+48=80 > 64 �� OVERFLOW */
        free(buf);
    }
}

int main(void) {
    static char src[80];
    edge_offset_overflow(src);  /* 32+48=80 > 64 */
    return 0;
}
