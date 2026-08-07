/* 安全: 循环写入全部在 free 之前. */
#include <stdlib.h>
#include <stdio.h>

int main(void) {
    char *p = (char *)malloc(16);
    if (!p) return 1;
    for (int i = 0; i < 16; i++) {
        p[i] = (char)i;
    }
    printf("%d\n", p[15]);
    free(p);
    return 0;
}
