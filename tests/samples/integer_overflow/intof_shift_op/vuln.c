#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* INTOF-06: 移位溢出 — 左移操作导致符号位翻转
 * CWE-190: Integer Overflow via bit shift in size computation */
int main(int argc, char **argv) {
    int n;
    if (argc < 2) n = 10;
    else n = atoi(argv[1]);

    /* VULNERABLE: n << 10 相当于 n*1024, 可能溢出 */
    int size = n << 10;
    if (size > 0) {
        char *buf = (char *)malloc(size);
        if (buf) {
            memset(buf, 0, n * 1024);  /* 原始乘法也可能溢出 */
            free(buf);
        }
    }
    return 0;
}
