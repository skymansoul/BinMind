#include <stdlib.h>
#include <stdio.h>

__attribute__((noinline)) void trigger_guard_safe(int flag) {
    char *p = (char *)malloc(64);
    if (!p) return;
    /* 在flag路径中, 使用和释放在同一分支内 */
    if (flag) {
        p[0] = 'X';  /* 先使用 */
        free(p);     /* 再释放 → 安全 */
        return;
    }
    free(p);         /* 不使用的路径直接释放 */
}

int main(void) {
    trigger_guard_safe(1);
    return 0;
}
