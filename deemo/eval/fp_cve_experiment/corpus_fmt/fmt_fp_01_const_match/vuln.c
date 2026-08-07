/* 安全: 常量格式串 "%s %d" 与实参匹配. */
#include <stdio.h>

int main(void) {
    printf("%s %d\n", "hello", 42);
    return 0;
}
