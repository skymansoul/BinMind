#include <string.h>
#include <stdlib.h>

__attribute__((noinline)) void write_after(const char *in, size_t n, size_t off) {
    char *buf = malloc(256);
    if (!buf) return;
    memcpy(buf + off, in, n);   /* VULN: off+n > 256 */
    volatile char probe = buf[0];   /* 观察堆写, 防DCE */
    (void)probe;
    free(buf);
}

int main(void) {
    char d[128];
    memset(d, 'B', 128);
    write_after(d, 128, 192);
    return 0;
}
