/* TN (safe) sample for heap-overflow benchmark */
#include <stdlib.h>
#include <string.h>
int main(void) {
    char src[128];
    memset(src, 'J', sizeof(src));
    char *other = (char *)malloc(32);
    char *buf = (char *)malloc(128);
    if (!buf) return -1;
    (void)other;
    memcpy(buf, src, 128);
    free(other);
    free(buf);
    return 0;
}
