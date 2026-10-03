/*
 * FMT-SAFE-CONST — 安全: 常量格式串无写说明符
 * printf("hello %d", x) 格式串为编译期常量.
 * 触发: 常规格式化输出.
 */
#include <stdio.h>

int main(void) {
    int x = 42;
    /* 安全: 常量格式串, 无 %n */
    printf("hello %d\n", x);
    return 0;
}
