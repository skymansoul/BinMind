/* TP-06: Conditional UAF (CWE-416) */
#include <stdlib.h>
void conditional_uaf(int do_free) {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    if (do_free) { free(buf); }
    buf[0] = 'X';  /* UAF when do_free==1 */
}
int main(void) { conditional_uaf(1); return 0; }