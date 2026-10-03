#include <string.h>
#include <stdlib.h>

void guarded_copy(const char *in, int len) {
    if (len > 512) return;      /* 守卫: len有界 */
    char *buf = malloc(len);
    if (!buf) return;
    memcpy(buf, in, len);       /* SAFE */
    free(buf);
}

int main(void) {
    char data[512];
    memset(data, 'G', 512);
    guarded_copy(data, 256);
    return 0;
}
