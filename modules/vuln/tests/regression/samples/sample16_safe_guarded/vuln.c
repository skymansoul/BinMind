/* sample16_safe_guarded: 安全代码 — 有边界检查守卫
 * Ground Truth: SAFE — malloc(size)后cmp检查再memcpy
 * Pattern: 静态分析应能利用边界守卫证明安全 (FP测试)
 */
#include <stdlib.h>
#include <string.h>
int main() {
    int size = 64;
    char *p = malloc(128);
    if (size <= 128) {
        memcpy(p, "SAFE_STRING_UNDER_128_BYTES_LONG", size);
    }
    free(p);
    return 0;
}
