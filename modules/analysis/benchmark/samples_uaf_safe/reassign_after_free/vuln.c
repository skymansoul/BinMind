#include <stdlib.h>
#include <stdio.h>

static char *g_p_reassign;

__attribute__((noinline)) void trigger_reassign_vuln(void) {
    g_p_reassign = (char *)malloc(64);
    char *saved = g_p_reassign;
    free(g_p_reassign);
    g_p_reassign = (char *)malloc(128);
    /* 使用已释放的旧指针，volatile防止编译器DCE */
    *(volatile char *)saved = 'X';
}

int main(void) {
    trigger_reassign_vuln();
    return 0;
}
