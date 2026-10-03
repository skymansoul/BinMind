/* uaf_12_store_through — free 后经指针存储 (TP)。
 * Expected: UAF */
#include <stdlib.h>

int main(void) {
    int *p = (int *)malloc(16);
    if (!p) return 1;
    free(p);
    *p = 0xdeadbeef;              /* store through dangling pointer */
    return 0;
}
