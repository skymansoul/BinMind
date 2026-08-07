
/* 良性: 早退守卫 — len > cap 直接返回, 拷贝仅在 len≤cap 可达. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static void early_exit(size_t len, const char *src) {
    char *dst = (char *)malloc(256);
    if (len > 256) return;           /* 早退 */
    memcpy(dst, src, len);
    free(dst);
}

int main(void) {
    char data[128];
    memset(data, 'Z', sizeof(data));
    early_exit(100, data);
    return 0;
}
