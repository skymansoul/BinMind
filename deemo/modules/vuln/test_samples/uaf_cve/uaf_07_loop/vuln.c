/* uaf_07_loop — 循环内 free 后使用 (TP)。
 * Expected: UAF */
#include <stdlib.h>

int main(void) {
    char *p = (char *)malloc(16);
    if (!p) return 1;
    for (int i = 0; i < 4; i++) {
        if (i == 2) free(p);
        if (i == 3) p[0] = 'B';   /* use after free */
    }
    return 0;
}
