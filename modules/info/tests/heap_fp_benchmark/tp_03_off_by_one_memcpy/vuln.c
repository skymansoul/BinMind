/* TP sample for heap-overflow benchmark */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char src[65];
    memset(src, 'B', sizeof(src));
    char *buf = (char *)malloc(64);
    if (!buf) return -1;
    memcpy(buf, src, 65);
    free(buf);
    return 0;
}
