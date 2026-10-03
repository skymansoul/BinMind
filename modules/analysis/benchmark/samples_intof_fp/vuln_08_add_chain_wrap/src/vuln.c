#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    unsigned n = argc > 1 ? (unsigned)atoi(argv[1]) : 0x7FFFFFFF;
    unsigned sz = n + n;                /* 加法回绕为 0xFFFFFFFE */
    char *buf = (char *)malloc(sz);
    if (!buf) return 1;
    memset(buf, 0, 0x1000);
    free(buf);
    return 0;
}
