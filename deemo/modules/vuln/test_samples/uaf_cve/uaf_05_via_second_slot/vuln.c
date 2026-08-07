/* uaf_05_via_second_slot — 别名栈槽 UAF (TP)。
 * Expected: UAF */
#include <stdlib.h>

int main(void) {
    char *buf = (char *)malloc(32);
    if (!buf) return 1;
    char *p = buf;
    free(p);
    char c = buf[1];              /* use via other slot */
    return c;
}
