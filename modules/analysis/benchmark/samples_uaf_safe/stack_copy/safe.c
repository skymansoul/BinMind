#include <stdlib.h>
#include <stdio.h>

__attribute__((noinline)) void trigger_stack_safe(void) {
    char *p = (char *)malloc(64);
    if (!p) return;
    char *saved = p;  /* 栈副本 */
    /* ... 许多代码 ... */
    saved[0] = 'X';  /* 使用前未释放 → 安全 */
    free(p);
}

int main(void) {
    trigger_stack_safe();
    return 0;
}
