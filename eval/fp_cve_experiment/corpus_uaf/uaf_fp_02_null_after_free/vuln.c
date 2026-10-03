/* 安全: free 后 p=NULL, 后续使用被 NULL 检查拦截. */
#include <stdlib.h>
#include <stdio.h>

int main(void) {
    char *p = (char *)malloc(16);
    if (!p) return 1;
    free(p);
    p = 0;
    if (p) {
        p[0] = 'X';
    }
    return 0;
}
