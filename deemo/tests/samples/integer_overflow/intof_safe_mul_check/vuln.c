#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
/* INTOF-SAFE-03: 乘法前用除法预检查上界, 乘积不会溢出 */
int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 4;
    int m = argc > 2 ? atoi(argv[2]) : 5;
    if (n <= 0 || m <= 0) return 1;
    if (n > INT_MAX / m) {                     /* 乘法溢出预检查 */
        fprintf(stderr, "product too large\n");
        return 1;
    }
    int total = n * m;                         /* 已证乘积在 int 范围内 */
    char *buf = (char *)malloc((size_t)total);
    if (buf) {
        memset(buf, 'C', (size_t)total);
        free(buf);
    }
    return 0;
}
