#include <stdio.h>
#include <stdlib.h>
/* UAF-03: 循环中释放，循环后使用 — 跨基本块生命周期 */
#define N 4
int main(void) {
    char *bufs[N];
    for (int i = 0; i < N; i++) {
        bufs[i] = (char *)malloc(64);
        if (!bufs[i]) return 1;
    }
    for (int i = 0; i < N; i++) free(bufs[i]);
    printf("use after loop: %s\n", bufs[0]);  /* VULNERABLE */
    return 0;
}
