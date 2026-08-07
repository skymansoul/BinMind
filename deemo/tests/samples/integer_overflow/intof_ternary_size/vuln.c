#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* INTOF-15: 三元运算中的溢出 — malloc参数在三元表达式中计算溢出
 * CWE-190: Integer Overflow in ternary expression argument to malloc */
int main(int argc, char **argv) {
    int n, m;
    if (argc < 2) { n = 100; m = 1; }
    else { n = atoi(argv[1]); m = argc; }

    /* VULNERABLE: n*m溢出, 且三元运算遮蔽了溢出检查 */
    size_t size = (n > 0 && m > 0) ? (n * m) : 64;
    char *buf = (char *)malloc(size);
    if (!buf) return 1;
    memset(buf, 'T', n * m);  /* 实际需要的大小超过分配 */
    free(buf);
    return 0;
}
