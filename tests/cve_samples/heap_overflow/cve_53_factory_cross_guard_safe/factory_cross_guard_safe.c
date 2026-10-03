#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * CVE-53: 工厂函数+跨函数guard安全
 *
 * 模式:
 *   char *make_buf(int sz) { if (sz > 128) sz = 128; return malloc(sz); }
 *   void fill_buf(char *b, int n) { if (n > 64) n = 64; memcpy(b, data, n); }
 *   main: int n = 200; buf = make_buf(n); fill_buf(buf, n);
 *   guard: sz<=128, n<=64, write_end=64 <= usable(128)=136 → SAFE
 */
char *make_buf(int sz) {
    if (sz > 128) sz = 128;
    return (char *)malloc(sz);
}

void fill_buf(char *b, int n) {
    if (n > 64) n = 64;
    char data[64];
    memset(data, 'J', 64);
    memcpy(b, data, n);
}

int main(int argc, char **argv) {
    int n = 200;
    if (argc > 1) n = atoi(argv[1]);

    char *buf = make_buf(n);
    if (!buf) return 1;
    fill_buf(buf, n);

    printf("factory_cross_guard_safe: n=%d\n", n);
    free(buf);
    return 0;
}
