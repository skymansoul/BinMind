/* 安全: free 之后没有任何对 p 的访问. */
#include <stdlib.h>
#include <stdio.h>

int main(void) {
    char *p = (char *)malloc(16);
    if (!p) return 1;
    p[0] = 'x';
    printf("%c\n", p[0]);
    free(p);
    return 0;
}
