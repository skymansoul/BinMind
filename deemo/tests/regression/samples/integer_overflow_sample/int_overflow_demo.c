/* 整数溢出→堆溢出: size + 1 wraparound */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void vulnerable(int n) {
    /* BUG: n+1 可能 wraparound 到 0 或极小值 */
    char *buf = (char *)malloc(n + 1);
    if (buf) {
        memset(buf, 'A', n);     /* n > alloc_size → HEAP OVERFLOW */
        buf[n] = 0;
        free(buf);
    }
}
int main(int argc, char **argv) {
    vulnerable(0xFFFFFFFF);      /* n+1 = 0, malloc(0) → memset 4GB */
    return 0;
}
