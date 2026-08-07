#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* INTOF-11: 递归中的整数溢出 — 递归深度乘缓冲区大小溢出
 * CWE-190: Integer Overflow in recursive size computation */
size_t calc_size(int depth, int base) {
    if (depth == 0) return base;
    /* VULNERABLE: 递归乘积累可能溢出 */
    return base * calc_size(depth - 1, base);
}
int main(void) {
    size_t s = calc_size(5, 0x40000000);
    /* 5次乘法后可能溢出 */
    char *buf = (char *)malloc(s);
    if (!buf) return 1;
    memset(buf, 0, s);
    free(buf);
    return 0;
}
