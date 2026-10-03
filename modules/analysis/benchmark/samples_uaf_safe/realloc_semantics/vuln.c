#include <stdlib.h>
#include <stdio.h>

__attribute__((noinline)) void trigger_realloc_vuln(void) {
    char *old = (char *)malloc(64);
    if (!old) return;
    char *saved = old;
    char *newp = (char *)realloc(old, 128);
    if (!newp) return;
    /* 使用旧指针，realloc可能导致内存移动，volatile防止编译器DCE */
    *(volatile char *)saved = 'X';
    free(newp);
}

int main(void) {
    trigger_realloc_vuln();
    return 0;
}
