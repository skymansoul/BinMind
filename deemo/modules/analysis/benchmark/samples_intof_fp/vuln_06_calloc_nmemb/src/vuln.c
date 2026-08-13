#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    unsigned n = argc > 1 ? (unsigned)atoi(argv[1]) : 0x20000000;
    char *buf = (char *)calloc(n * 4, 16);  /* 调用点乘法溢出 */
    if (!buf) return 1;
    for (unsigned i = 0; i < 100; i++) buf[i] = (char)i;
    free(buf);
    return 0;
}
