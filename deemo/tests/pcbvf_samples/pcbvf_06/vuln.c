#include <stdlib.h>
#include <string.h>

void process(char *src, int size) {
    char *buf = malloc(size);
    if (!buf) return;
    if (size > 0 && size <= 1024) memcpy(buf, src, size);
    free(buf);
}
