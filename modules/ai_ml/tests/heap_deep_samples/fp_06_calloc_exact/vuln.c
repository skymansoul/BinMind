#include <string.h>
#include <stdlib.h>

void exact_grid(const char *in) {
    char *buf = calloc(16, 64);   /* 1024 */
    if (!buf) return;
    memcpy(buf, in, 1024);        /* copy==alloc → SAFE */
    free(buf);
}

int main(void) {
    char data[1024];
    memset(data, 'K', 1024);
    exact_grid(data);
    return 0;
}
