/* uaf_02_simple_write — free 后写 (TP)。
 * Expected: UAF */
#include <stdlib.h>

int main(void) {
    char *p = (char *)malloc(32);
    if (!p) return 1;
    free(p);
    p[0] = 'A';                   /* use-after-free write */
    return 0;
}
