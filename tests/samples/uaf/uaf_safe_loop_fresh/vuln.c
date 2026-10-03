#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* UAF-SAFE-06: 循环内每轮迭代重新分配, 迭代内使用完毕即释放, 无跨迭代使用 */
int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 3;
    if (n < 0) n = 3;
    for (int i = 0; i < n; i++) {
        char *p = (char *)malloc(64);
        if (!p) return 1;
        snprintf(p, 64, "item %d", i);
        printf("%s\n", p);
        free(p);  /* 迭代内释放, 下一轮重新分配 */
    }
    return 0;
}
