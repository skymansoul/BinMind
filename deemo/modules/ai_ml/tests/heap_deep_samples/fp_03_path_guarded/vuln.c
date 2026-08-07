#include <string.h>
#include <stdlib.h>

void guarded(const char *in, int len) {
    char *buf = malloc(256);
    if (!buf) return;
    if (len > 256) return;      /* 守卫: len<=256=usable */
    memcpy(buf, in, len);       /* SAFE */
    free(buf);
}

int main(void) {
    char data[256];
    memset(data, 'H', 256);
    guarded(data, 128);
    return 0;
}
