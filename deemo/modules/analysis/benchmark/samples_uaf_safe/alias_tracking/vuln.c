#include <stdlib.h>
#include <stdio.h>

__attribute__((noinline)) void trigger_alias_vuln(void) {
    char *p = (char *)malloc(64);
    if (!p) return;
    char *q = p;
    free(p);
    /* 通过别名访问已释放内存，volatile防止编译器DCE */
    *(volatile char *)q = 'X';
}

int main(void) {
    trigger_alias_vuln();
    return 0;
}
