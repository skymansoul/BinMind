#include <stdlib.h>
#include <stdio.h>

__attribute__((noinline)) void trigger_stack_vuln(void) {
    char *p = (char *)malloc(64);
    if (!p) return;
    char *saved = p;
    free(p);
    /* 使用栈上的旧指针，volatile防止编译器DCE */
    *(volatile char *)saved = 'X';
}

int main(void) {
    trigger_stack_vuln();
    return 0;
}
