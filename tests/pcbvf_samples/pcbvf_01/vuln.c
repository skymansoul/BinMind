#include <stdlib.h>
#include <string.h>

void process(char *src, int len) {
    char *buf = malloc(64);
    if (!buf) return;
    if (len <= 64) memcpy(buf, src, len);
    free(buf);
}
