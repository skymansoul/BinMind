#include <stdlib.h>
#include <string.h>

void process(char *src, int len) {
    char *buf = malloc(128);
    if (!buf) return;
    if (len >= 0 && len <= 128) memcpy(buf, src, len);
    free(buf);
}
