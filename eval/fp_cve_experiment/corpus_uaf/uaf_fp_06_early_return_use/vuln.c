/* 安全: use 在不经过 free 的提前返回路径上. */
#include <stdlib.h>
#include <stdio.h>

int process(char *p, int flag) {
    if (flag) {
        return p[0];
    }
    free(p);
    return 0;
}

int main(void) {
    char *p = (char *)malloc(16);
    if (!p) return 1;
    int r = process(p, 1);
    free(p);
    printf("%d\n", r);
    return 0;
}
