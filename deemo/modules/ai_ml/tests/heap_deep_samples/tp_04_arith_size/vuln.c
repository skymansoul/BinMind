#include <string.h>
#include <stdlib.h>

__attribute__((noinline)) void read_line(const char *input, int n) {
    int sz = n * 2;
    char *buf = malloc(sz);
    if (!buf) return;
    memcpy(buf, input, n * 4);   /* VULN: n*4 > n*2 */
    volatile char probe = buf[0];   /* 观察堆写, 防DCE */
    (void)probe;
    free(buf);
}

int main(void) {
    char big[4096];
    memset(big, 'C', 4096);
    read_line(big, 256);
    return 0;
}
