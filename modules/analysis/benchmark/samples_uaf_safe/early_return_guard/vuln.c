#include <stdlib.h>
#include <stdio.h>

__attribute__((noinline)) void trigger_guard_vuln(int flag) {
    char *p = (char *)malloc(64);
    if (!p) return;
    if (flag) {
        free(p);
        /* missing return falls through to UAF */
    }
    /* flag=1: UAF; flag=0: safe use，volatile防止编译器DCE */
    *(volatile char *)p = 'X';
    if (!flag) free(p);
}

int main(void) {
    trigger_guard_vuln(1);
    return 0;
}
