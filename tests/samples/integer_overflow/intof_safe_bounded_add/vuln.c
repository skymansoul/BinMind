#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
/* INTOF-SAFE-01: 加法前显式上界检查, 溢出路径提前拒绝, total 不会回绕 */
int main(int argc, char **argv) {
    int size = 100;
    int extra = argc > 1 ? atoi(argv[1]) : 20;
    if (extra < 0 || extra > INT_MAX - size) {  /* 加法溢出预检查 */
        fprintf(stderr, "rejected: extra out of range\n");
        return 1;
    }
    int total = size + extra;          /* 已证不回绕 */
    char *buf = (char *)malloc((size_t)total);
    if (buf) {
        memset(buf, 'A', (size_t)total);
        free(buf);
    }
    return 0;
}
