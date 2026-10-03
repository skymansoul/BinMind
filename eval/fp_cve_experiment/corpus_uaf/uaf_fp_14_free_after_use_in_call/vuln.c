/* 安全: printf 使用 p 后 free. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char *p = (char *)malloc(16);
    if (!p) return 1;
    strcpy(p, "seq");
    printf("%s\n", p);
    free(p);
    return 0;
}
