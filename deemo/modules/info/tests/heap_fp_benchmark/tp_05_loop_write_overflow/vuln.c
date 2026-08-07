/* TP sample for heap-overflow benchmark */
#include <stdlib.h>
int main(void) {
    char *buf = (char *)malloc(16);
    if (!buf) return -1;
    int i = 0;
    while (i < 64) { buf[i++] = 'D'; }
    free(buf);
    return 0;
}
