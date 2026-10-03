/* uaf_04_alias_reg — 寄存器别名 UAF (TP)。
 * Expected: UAF */
#include <stdlib.h>

int main(void) {
    int *buf = (int *)malloc(64);
    if (!buf) return 1;
    int *p = buf;
    free(p);
    return buf[0];                /* use via alias */
}
