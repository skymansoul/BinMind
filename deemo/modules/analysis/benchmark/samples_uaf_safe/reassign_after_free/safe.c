#include <stdlib.h>
#include <stdio.h>

static char *g_p_reassign;

__attribute__((noinline)) void trigger_reassign_safe(void) {
    g_p_reassign = (char *)malloc(64);
    free(g_p_reassign);
    g_p_reassign = (char *)malloc(128);  /* 新分配 */
    g_p_reassign[0] = 'X';  /* 使用新指针 → 安全 */
}

int main(void) {
    trigger_reassign_safe();
    return 0;
}
