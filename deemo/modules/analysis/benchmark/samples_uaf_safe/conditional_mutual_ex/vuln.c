#include <stdlib.h>
#include <stdio.h>

__attribute__((noinline)) void trigger_cond_vuln(int err) {
    char *p = (char *)malloc(64);
    if (!p) return;
    if (err > 0) {
        free(p);
    }
    /* 根据err值，可能到达此处，volatile防止编译器DCE */
    *(volatile char *)p = 'X';
}

int main(void) {
    trigger_cond_vuln(1);
    return 0;
}
