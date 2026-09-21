#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* INTOF-SAFE-02: 运算前拒绝负值并宽化到 size_t, 无符号加法不会回绕成小值 */
int main(int argc, char **argv) {
    int a = argc > 1 ? atoi(argv[1]) : 10;
    int b = argc > 2 ? atoi(argv[2]) : 20;
    if (a < 0 || b < 0) return 1;              /* 负值拒绝 */
    size_t total = (size_t)a + (size_t)b;      /* 宽化后相加 */
    if (total > 4096) {                        /* 上限保护 */
        fprintf(stderr, "too large\n");
        return 1;
    }
    char *buf = (char *)malloc(total);
    if (buf) {
        memset(buf, 'B', total);
        free(buf);
    }
    return 0;
}
