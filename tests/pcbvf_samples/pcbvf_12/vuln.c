#include <stdlib.h>
#include <string.h>

void process(char *src, int count) {
    char *buf = malloc(count * 4);
    if (!buf) return;
    if (count > 16) memcpy(buf, src, count * 4);
    free(buf);
}
