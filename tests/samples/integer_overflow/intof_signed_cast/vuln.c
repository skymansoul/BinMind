#include <stdio.h>
#include <stdlib.h>
/* INTOF-04: 有符号→无符号截断 — 负数转为大无符号数
 * CWE-681: Signed to Unsigned Conversion Error */
int main(int argc, char **argv) {
    int signed_size;
    if (argc < 2) signed_size = 64;
    else signed_size = atoi(argv[1]);

    /* VULNERABLE: 如果signed_size为负, 转size_t后变成巨大值 */
    size_t alloc_size = (size_t)signed_size;
    char *buf = (char *)malloc(alloc_size);  /* 分配失败或分配巨大 */
    if (!buf) return 1;
    buf[0] = 'X';
    free(buf);
    return 0;
}
