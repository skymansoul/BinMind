/* uaf_06_conditional — 条件分支 free 后使用 (TP)。
 * Expected: UAF */
#include <stdlib.h>

int main(int argc, char **argv) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    if (argc > 1) free(p);
    return p[0];                  /* use after conditional free */
}
