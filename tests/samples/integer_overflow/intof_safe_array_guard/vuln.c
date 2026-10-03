#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* INTOF-SAFE-04: 数组索引前完整边界检查, 写入索引必在界内 */
int main(int argc, char **argv) {
    int idx = argc > 1 ? atoi(argv[1]) : 5;
    int buf[64];
    memset(buf, 0, sizeof(buf));
    if (idx < 0 || idx >= 64) {                /* 索引边界检查 */
        fprintf(stderr, "index out of range\n");
        return 1;
    }
    buf[idx] = 42;                             /* 已证索引在界内 */
    printf("buf[%d]=%d\n", idx, buf[idx]);
    return 0;
}
