/* TN (safe) sample for heap-overflow benchmark */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char src[128];
    memset(src, 'A', sizeof(src));
    char *buf = (char *)malloc(128);
    if (!buf) return -1;
    memcpy(buf, src, 128);
    free(buf);
    return 0;
}
