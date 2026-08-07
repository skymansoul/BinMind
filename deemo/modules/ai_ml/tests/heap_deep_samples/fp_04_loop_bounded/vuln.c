#include <string.h>
#include <stdlib.h>

void fill_blocks(const char *src) {
    char *dst = malloc(512);
    if (!dst) return;
    for (int i = 0; i < 32; i++) {
        memcpy(dst + i * 16, src, 16);   /* 32*16=512 ≤ 512 */
    }
    free(dst);
}

int main(void) {
    char s[16];
    memset(s, 'I', 16);
    fill_blocks(s);
    return 0;
}
