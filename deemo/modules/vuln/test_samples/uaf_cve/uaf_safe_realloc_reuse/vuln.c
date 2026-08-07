/* uaf_safe_realloc_reuse — free 后 malloc 复用 (TN)。
 * Expected: SAFE */
#include <stdlib.h>

int main(void) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    free(p);
    p = (char *)malloc(64);       /* new object, same slot */
    if (!p) return 1;
    int v = p[0];                 /* deref of new object */
    free(p);
    return v;
}
