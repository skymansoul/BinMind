#include <string.h>
#include <stdlib.h>

void bounded_string(const char *in, int n) {
    if (n > 4096) return;
    char *buf = malloc(n);
    if (!buf) return;
    strncpy(buf, in, n);   /* copy==alloc → SAFE */
    free(buf);
}

int main(void) {
    char data[64];
    memset(data, 'L', 63);
    data[63] = 0;
    bounded_string(data, 64);
    return 0;
}
