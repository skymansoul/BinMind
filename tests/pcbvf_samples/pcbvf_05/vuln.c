#include <stdlib.h>
#include <string.h>

void process(char *src, int n) {
    char *buf = malloc(n);
    if (!buf) return;
    if (n <= 256) {
        memcpy(buf, src, n);
    }
    free(buf);
}
