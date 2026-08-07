#include <string.h>
#include <stdlib.h>

void safe_copy(const char *in, int len) {
    char *buf = malloc(len);
    if (!buf) return;
    memcpy(buf, in, len);   /* SAFE: copy==alloc */
    free(buf);
}

int main(void) {
    char data[128];
    memset(data, 'S', 128);
    safe_copy(data, 128);
    return 0;
}
