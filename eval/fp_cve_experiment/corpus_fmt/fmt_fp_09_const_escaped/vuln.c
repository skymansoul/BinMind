/* 安全: "%%d" 转义后无说明符, 常量安全. */
#include <stdio.h>

int main(void) {
    printf("literal %%d\n");
    return 0;
}
