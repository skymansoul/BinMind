#include <string.h>
#include <stdlib.h>

__attribute__((noinline)) void shrink_and_copy(const char *in, size_t n) {
    char *buf = malloc(512);
    if (!buf) return;
    buf = realloc(buf, 128);   /* 收缩到128 */
    if (!buf) return;
    memcpy(buf, in, n);        /* VULN: n=256 > 128 */
    volatile char probe = buf[0];   /* 观察堆写, 防DCE */
    (void)probe;
    free(buf);
}

int main(void) {
    char big[512];
    memset(big, 'E', 512);
    shrink_and_copy(big, 256);
    return 0;
}
