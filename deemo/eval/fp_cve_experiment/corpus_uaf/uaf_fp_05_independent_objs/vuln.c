/* 安全: a/b 独立对象, 释放 a 后写入 b. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char *a = (char *)malloc(16);
    char *b = (char *)malloc(16);
    if (!a || !b) return 1;
    strcpy(a, "aaaa");
    strcpy(b, "bbbb");
    free(a);
    b[0] = 'B';
    printf("%s\n", b);
    free(b);
    return 0;
}
