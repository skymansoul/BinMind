/* 安全: 常量格式串含位置参数, 实参存在. */
#include <stdio.h>

int main(void) {
    printf("%2$d %1$d\n", 10, 20);
    return 0;
}
