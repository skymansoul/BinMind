/* 安全: free(p) 后 p 重新 malloc, 后续使用新对象. */
#include <stdlib.h>
#include <stdio.h>

int main(void) {
    char *p = (char *)malloc(16);
    if (!p) return 1;
    free(p);
    p = (char *)malloc(16);
    if (!p) return 1;
    p[0] = 'R';
    printf("%c\n", p[0]);
    free(p);
    return 0;
}
