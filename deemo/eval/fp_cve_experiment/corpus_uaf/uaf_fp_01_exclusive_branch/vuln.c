/* 安全: if/else 互斥 — free 与 use 各自独占一个分支. */
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv) {
    (void)argv;
    char *p = (char *)malloc(16);
    if (!p) return 1;
    if (argc > 1) {
        free(p);
    } else {
        p[0] = 'S';
        printf("%c\n", p[0]);
        free(p);
    }
    return 0;
}
