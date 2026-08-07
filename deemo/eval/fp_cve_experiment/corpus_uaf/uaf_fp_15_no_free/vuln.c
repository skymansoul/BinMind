/* 安全: 无释放操作, 不构成 UAF. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    strcpy(p, "leak-ok");
    printf("%s\n", p);
    return 0;
}
