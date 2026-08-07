#include <string.h>
#include <stdlib.h>

void small_write(const char *in) {
    char *buf = malloc(512);
    if (!buf) return;
    memcpy(buf, in, 64);   /* 64 ≤ usable(512) → SAFE */
    free(buf);
}

int main(void) {
    char data[64];
    memset(data, 'N', 64);
    small_write(data);
    return 0;
}
