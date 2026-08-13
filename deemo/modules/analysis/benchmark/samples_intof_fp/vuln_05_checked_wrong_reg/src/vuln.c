#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    unsigned n = argc > 1 ? (unsigned)atoi(argv[1]) : 0x40000000;
    unsigned flag = argc;
    size_t sz = (size_t)n * 4;
    if (flag == 0) return 1;            /* 检查 flag, 非 sz */
    char *buf = (char *)malloc(sz);
    if (!buf) return 1;
    memset(buf, 0, 0x1000);
    free(buf);
    return 0;
}
