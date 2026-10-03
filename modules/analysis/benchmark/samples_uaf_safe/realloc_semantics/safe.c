#include <stdlib.h>
#include <stdio.h>

__attribute__((noinline)) void trigger_realloc_safe(void) {
    char *p = (char *)malloc(64);
    if (!p) return;
    p = (char *)realloc(p, 128);  /* p更新为新指针 */
    if (!p) return;
    p[0] = 'X';  /* 使用更新后的p → 安全 */
    free(p);
}

int main(void) {
    trigger_realloc_safe();
    return 0;
}
