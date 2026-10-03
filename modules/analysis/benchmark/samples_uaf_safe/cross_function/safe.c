#include <stdlib.h>
#include <stdio.h>

static char *g_cross_s;

__attribute__((noinline)) void cross_alloc(char **pp) {
    *pp = (char *)malloc(64);  /* 在callee中分配 */
}

__attribute__((noinline)) void trigger_cross_safe(void) {
    g_cross_s = NULL;
    cross_alloc(&g_cross_s);   /* 通过callee分配 */
    if (g_cross_s) g_cross_s[0] = 'X';  /* 使用前未释放 → 安全 */
    free(g_cross_s);
}

int main(void) {
    trigger_cross_safe();
    return 0;
}
