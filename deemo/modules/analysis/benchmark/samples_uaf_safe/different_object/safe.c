#include <stdlib.h>
#include <stdio.h>

__attribute__((noinline)) void trigger_diffobj_safe(void) {
    char *p = (char *)malloc(64);
    char *q = (char *)malloc(64);
    free(p);
    q[0] = 'X';  /* 使用独立的q → 安全 */
    free(q);
}

int main(void) {
    trigger_diffobj_safe();
    return 0;
}
