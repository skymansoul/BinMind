#include <stdlib.h>
#include <stdio.h>

__attribute__((noinline)) void trigger_cond_safe(int err) {
    char *p = (char *)malloc(64);
    if (!p) return;
    if (err > 0) {
        free(p);
        return;  /* 释放后立即返回 → use不可达 */
    }
    p[0] = 'X';  /* 仅err≤0时到达 → 安全 */
}

int main(void) {
    trigger_cond_safe(0);
    return 0;
}
