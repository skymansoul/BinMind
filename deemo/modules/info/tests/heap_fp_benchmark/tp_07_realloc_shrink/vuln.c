/* TP sample for heap-overflow benchmark */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char src[128];
    memset(src, 'F', sizeof(src));
    char *buf = (char *)malloc(256);
    if (!buf) return -1;
    buf = (char *)realloc(buf, 16);
    if (!buf) return -1;
    memcpy(buf, src, 128);
    free(buf);
    return 0;
}
