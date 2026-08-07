/* safe_disjoint_allocs — 安全对照: 两次独立 malloc, 各自在分配范围内访问
 * SHIELD disjointness_prover 应该证明两次访问都在各自分配范围内 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *a = (char *)malloc(64);
    char *b = (char *)malloc(128);
    if (a && b) {
        memset(a, 0x41, 60);   // 安全: 60 < 64
        memset(b, 0x42, 120);  // 安全: 120 < 128
        printf("safe_disjoint: a[0]=%c b[0]=%c\n", a[0], b[0]);
        free(a); free(b);
    }
    return 0;
}
