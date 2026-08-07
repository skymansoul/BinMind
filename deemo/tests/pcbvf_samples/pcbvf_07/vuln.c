#include <stdlib.h>
#include <string.h>

void process(char *src, int n) {
    char *buf = malloc(256);
    if (!buf) return;
    if (n > 0) memcpy(buf, src, n);
    free(buf);
}
