/* TN (safe) sample for heap-overflow benchmark */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char src[256];
    memset(src, 'N', sizeof(src));
    char *buf = (char *)malloc(64);
    if (!buf) return -1;
    buf = (char *)realloc(buf, 256);
    if (!buf) return -1;
    memcpy(buf, src, 256);
    free(buf);
    return 0;
}
