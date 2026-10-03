/* 安全: 释放 p 后使用的是值副本 (非指针解引用). */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char *p = (char *)malloc(16);
    if (!p) return 1;
    strcpy(p, "copy-me");
    int v = p[0];
    free(p);
    printf("%c\n", v);
    return 0;
}
