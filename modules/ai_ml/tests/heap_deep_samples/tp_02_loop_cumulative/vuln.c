#include <string.h>
#include <stdlib.h>

__attribute__((noinline)) void build(const char *src, size_t per, int iters) {
    char *dst = malloc(per * 8);   /* 仅容纳8次迭代 */
    if (!dst) return;
    size_t off = 0;
    for (int i = 0; i < iters; i++) {   /* iters可>8 */
        memcpy(dst + off, src, per);
        off += per;
    }
    volatile char probe = dst[0];   /* 观察堆写, 防DCE */
    (void)probe;
    free(dst);
}

int main(void) {
    char s[64];
    memset(s, 'x', 64);
    build(s, 64, 32);
    return 0;
}
