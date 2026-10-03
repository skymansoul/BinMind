#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    unsigned n = argc > 1 ? (unsigned)atoi(argv[1]) : 64;
    n &= 0xFFFF;                       /* n <= 65535 */
    char *buf = (char *)malloc(n << 2);/* 乘积 <= 262140 */
    if (!buf) return 1;
    memset(buf, 0, (size_t)n << 2);
    free(buf);
    return 0;
}
