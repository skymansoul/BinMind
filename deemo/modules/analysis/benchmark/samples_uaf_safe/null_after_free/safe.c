#include <stdlib.h>
#include <stdio.h>

static char *g_p_null;

__attribute__((noinline)) void trigger_null_after_free_safe(void) {
    g_p_null = (char *)malloc(64);
    if (!g_p_null) return;
    free(g_p_null);
    g_p_null = NULL;  /* 显式置NULL → 后续访问是NULL deref, 不是UAF */
    if (g_p_null) g_p_null[0] = 'X';  /* NULL guard prevents access */
}

int main(void) {
    trigger_null_after_free_safe();
    return 0;
}
