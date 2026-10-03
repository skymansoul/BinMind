/* uaf_safe_use_before_free — 先使用后释放 (TN)。
 * Expected: SAFE */
#include <stdlib.h>

int main(void) {
    int *p = (int *)malloc(64);
    if (!p) return 1;
    int v = p[0];                 /* use before free */
    free(p);
    return v;
}
