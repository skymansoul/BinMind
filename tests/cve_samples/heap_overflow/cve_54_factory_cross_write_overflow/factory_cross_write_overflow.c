#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * CVE-54: 工厂函数+跨函数写入溢出
 *
 * 模式:
 *   char *make_buf(int sz) { return malloc(sz); }
 *   void fill_buf(char *b, int n) { memcpy(b, data, n); }
 *   main: int n = 200; buf = make_buf(32); fill_buf(buf, n);
 *   alloc=32 usable=40, write=200 > 40 → OVERFLOW
 */
char *make_buf(int sz) {
    return (char *)malloc(sz);
}

void fill_buf(char *b, int n) {
    char data[256];
    memset(data, 'K', 256);
    memcpy(b, data, n);
}

int main(int argc, char **argv) {
    int n = 200;
    if (argc > 1) n = atoi(argv[1]);

    char *buf = make_buf(32);
    if (!buf) return 1;
    fill_buf(buf, n);

    printf("factory_cross_write_overflow: n=%d\n", n);
    free(buf);
    return 0;
}
