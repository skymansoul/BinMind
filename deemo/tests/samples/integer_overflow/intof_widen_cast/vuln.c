#include <stdio.h>
#include <stdlib.h>
/* INTOF-14: 符号扩展溢出 — 窄有符号类型扩展到宽类型
 * CWE-194: Unexpected Sign Extension */
int main(int argc, char **argv) {
    short s;
    if (argc < 2) s = 100;
    else s = (short)atoi(argv[1]);

    /* VULNERABLE: 负的short扩展到size_t变成巨大正数 */
    size_t alloc = (size_t)s;
    char *buf = (char *)malloc(alloc);
    if (!buf) return 1;
    buf[0] = 'Z';
    free(buf);
    return 0;
}
