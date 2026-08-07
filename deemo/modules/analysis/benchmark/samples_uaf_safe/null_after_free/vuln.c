#include <stdlib.h>
#include <stdio.h>

static char *g_p_null;

__attribute__((noinline)) void trigger_null_after_free_vuln(void) {
    g_p_null = (char *)malloc(64);
    if (!g_p_null) return;
    free(g_p_null);
    /* 未置NULL 则 UAF，volatile防止编译器DCE */
    *(volatile char *)g_p_null = 'X';
}

int main(void) {
    trigger_null_after_free_vuln();
    return 0;
}
