#include <stdlib.h>
#include <stdio.h>

__attribute__((noinline)) void trigger_alias_safe(void) {
    char *p = (char *)malloc(64);
    if (!p) return;
    char *q = p;  /* 别名 */
    /* p和q指向同一对象, 但只在free前使用 */
    q[0] = 'X';  /* 使用别名(释放前) → 安全 */
    free(p);
    /* 无后续使用 */
}

int main(void) {
    trigger_alias_safe();
    return 0;
}
