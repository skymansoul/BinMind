/* uaf_09_after_call — 无关调用后 UAF (TP)。
 * Expected: UAF */
#include <stdlib.h>

static void busy(void) {}

int main(void) {
    char *p = (char *)malloc(32);
    if (!p) return 1;
    free(p);
    busy();                       /* unrelated call */
    return p[0];                  /* use after free */
}
