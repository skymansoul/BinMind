/* uaf_safe_other_object — free A 后使用 B (TN)。
 * Expected: SAFE */
#include <stdlib.h>

int main(void) {
    int *a = (int *)malloc(64);
    int *b = (int *)malloc(64);
    if (!a || !b) return 1;
    free(a);
    return b[0];                  /* b still live */
}
