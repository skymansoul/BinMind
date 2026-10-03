#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    unsigned n = argc > 1 ? (unsigned)atoi(argv[1]) : 16;
    n &= 0xFFF;                        /* 掩码约束: n <= 4095 */
    char *buf = (char *)malloc(n * 4); /* 乘积 <= 16380, 无溢出 */
    if (!buf) return 1;
    memset(buf, 0, n * 4);
    free(buf);
    return 0;
}
