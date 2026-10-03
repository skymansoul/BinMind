#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* INTOF-08: API返回值溢出 — read/recv返回值用于分配时未检查溢出
 * CWE-190: Integer Overflow from untrusted return value */
int main(void) {
    int n;
    fprintf(stderr, "enter count: ");
    if (fscanf(stdin, "%d", &n) != 1) return 1;

    /* VULNERABLE: n*2乘法溢出, n可能来自文件/网络 */
    int alloc = n * 2;
    char *buf = (char *)malloc(alloc);
    if (!buf) return 1;
    memset(buf, 'B', alloc);
    free(buf);
    return 0;
}
