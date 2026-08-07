#include <stdlib.h>
#include <stdio.h>

static char *g_cross;

__attribute__((noinline)) void cross_free(char **pp) {
    free(*pp);
}

__attribute__((noinline)) void trigger_cross_vuln(void) {
    g_cross = (char *)malloc(64);
    if (!g_cross) return;
    cross_free(&g_cross);
    /* g_cross已被callee释放，volatile防止编译器DCE */
    *(volatile char *)g_cross = 'X';
}

int main(void) {
    trigger_cross_vuln();
    return 0;
}
