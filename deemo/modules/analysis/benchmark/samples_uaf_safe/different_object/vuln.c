#include <stdlib.h>
#include <stdio.h>

__attribute__((noinline)) void trigger_diffobj_vuln(void) {
    char *p = (char *)malloc(64);
    char *q = (char *)malloc(64);
    free(p);
    /* 使用已释放的p，volatile防止编译器DCE */
    *(volatile char *)p = 'X';
    free(q);
}

int main(void) {
    trigger_diffobj_vuln();
    return 0;
}
