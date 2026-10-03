/* TN (safe) sample for heap-overflow benchmark */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char src[28];
    memset(src, 'E', sizeof(src));
    char *buf = (char *)malloc(28);
    if (!buf) return -1;
    memcpy(buf, src, 28);
    free(buf);
    return 0;
}
