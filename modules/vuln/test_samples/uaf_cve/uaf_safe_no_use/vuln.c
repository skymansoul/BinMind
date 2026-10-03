/* uaf_safe_no_use — free 后无使用 (TN)。
 * Expected: SAFE */
#include <stdlib.h>

int main(void) {
    char *p = (char *)malloc(32);
    if (!p) return 1;
    free(p);
    return 0;
}
