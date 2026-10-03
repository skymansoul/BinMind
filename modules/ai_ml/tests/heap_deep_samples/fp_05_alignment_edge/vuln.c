#include <string.h>
#include <stdlib.h>

void aligned_copy(const char *in) {
    char *buf = malloc(32);
    if (!buf) return;
    memcpy(buf, in, 40);   /* usable(32)=40 → SAFE */
    free(buf);
}

int main(void) {
    char data[40];
    memset(data, 'J', 40);
    aligned_copy(data);
    return 0;
}
