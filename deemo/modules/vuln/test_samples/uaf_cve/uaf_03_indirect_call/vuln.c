/* uaf_03_indirect_call — free 后经悬垂指针调用 (TP)。
 * Expected: UAF */
#include <stdlib.h>

static void h(void) {}

int main(void) {
    void (**fp)() = (void (**)())malloc(16);
    if (!fp) return 1;
    *fp = h;
    free(fp);
    (**fp)();                     /* use-after-free indirect call */
    return 0;
}
