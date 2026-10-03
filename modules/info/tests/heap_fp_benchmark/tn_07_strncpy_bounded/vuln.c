/* TN (safe) sample for heap-overflow benchmark */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char src[256];
    memset(src, 'G', sizeof(src));
    char *buf = (char *)malloc(128);
    if (!buf) return -1;
    strncpy(buf, src, 127);
    free(buf);
    return 0;
}
