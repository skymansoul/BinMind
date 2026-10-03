/* TP sample for heap-overflow benchmark */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char src[64];
    memset(src, 'A', sizeof(src));
    char *buf = (char *)malloc(32);
    if (!buf) return -1;
    memcpy(buf, src, 64);
    free(buf);
    return 0;
}
