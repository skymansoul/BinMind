
/* 良性: 钳位守卫 — size 先钳到 64 再拷贝到 malloc(64).
   守卫支配拷贝点, ACPE 守卫分析应滤除。 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static void guarded_copy(size_t n, const char *src) {
    char *dst = (char *)malloc(64);
    if (n > 64) n = 64;              /* 钳位 */
    memcpy(dst, src, n);
    free(dst);
}

int main(void) {
    char data[256];
    memset(data, 'Y', sizeof(data));
    guarded_copy(128, data);
    guarded_copy(8, data);
    return 0;
}
