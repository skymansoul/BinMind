#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static size_t calc_size(unsigned n) {
    return (size_t)(n * 4);             /* 32 位乘法溢出 */
}
int main(int argc, char **argv) {
    unsigned n = argc > 1 ? (unsigned)atoi(argv[1]) : 0x40000000;
    char *buf = (char *)malloc(calc_size(n));
    if (!buf) return 1;
    memset(buf, 0, 0x1000);
    free(buf);
    return 0;
}
