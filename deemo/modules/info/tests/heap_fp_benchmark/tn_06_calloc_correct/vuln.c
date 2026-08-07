/* TN (safe) sample for heap-overflow benchmark */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char src[64];
    memset(src, 'F', sizeof(src));
    int *buf = (int *)calloc(16, sizeof(int));
    if (!buf) return -1;
    memcpy(buf, src, 64);
    free(buf);
    return 0;
}
