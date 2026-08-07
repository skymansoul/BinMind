#include <stdlib.h>
#include <string.h>

void process(char *src, int n) {
    char *buf = malloc(n + 16);
    if (!buf) return;
    if (n > 0 && n <= 64) memcpy(buf, src, n);
    free(buf);
}
