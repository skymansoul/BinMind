/* TN (safe) sample for heap-overflow benchmark */
#include <stdlib.h>
int main(void) {
    char *buf = (char *)malloc(64);
    if (!buf) return -1;
    buf[32] = 'M';
    free(buf);
    return 0;
}
