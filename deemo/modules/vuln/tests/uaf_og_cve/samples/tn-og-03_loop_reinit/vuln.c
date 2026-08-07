/* TN 对照 3: 循环重建 — 每轮迭代 free(p); p = malloc(); use(p).
   每次迭代生成新对象代际, use 与 free 不同代际. */

#include <stdio.h>
#include <stdlib.h>

int main(void) {
    int i;
    int *p;
    for (i = 0; i < 4; i++) {
        p = (int *)malloc(16);
        if (!p) {
            return 1;
        }
        *p = i;
        free(p);
        p = (int *)malloc(16);
        if (!p) {
            return 1;
        }
        *p = i * 2;
        printf("%d\n", *p);
        free(p);
    }
    return 0;
}
