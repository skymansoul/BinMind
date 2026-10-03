/* uaf_01_simple_read — free 后解引用读取 (TP)。
 * Expected: UAF */
#include <stdlib.h>

int main(void) {
    int *p = (int *)malloc(64);
    if (!p) return 1;
    free(p);
    int v = p[0];                 /* use-after-free read */
    return v;
}
