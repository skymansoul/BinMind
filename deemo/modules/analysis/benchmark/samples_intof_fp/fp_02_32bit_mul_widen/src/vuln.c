#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    unsigned a = argc > 1 ? (unsigned)atoi(argv[1]) : 1000;
    a &= 0xFFF;                        /* 掩码: a <= 4095 */
    unsigned b = 8;
    char *buf = (char *)malloc((size_t)a * b);  /* <= 32760 */
    if (!buf) return 1;
    memset(buf, 0, (size_t)a * b);
    free(buf);
    return 0;
}
