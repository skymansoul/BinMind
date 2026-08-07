/* 安全: 写入发生在 free 之前, 线性序正确. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char *p = (char *)malloc(16);
    if (!p) return 1;
    strcpy(p, "first");
    printf("%s\n", p);
    free(p);
    return 0;
}
