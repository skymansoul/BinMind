/* TP sample for heap-overflow benchmark */
#include <stdlib.h>
int main(void) {
    char *buf = (char *)malloc(64);
    if (!buf) return -1;
    int i = 0;
    while (i < 128) { buf[i++] = 'J'; }
    free(buf);
    return 0;
}
