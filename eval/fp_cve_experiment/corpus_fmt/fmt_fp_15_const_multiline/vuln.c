/* 安全: 相邻字符串字面量拼接为常量格式串. */
#include <stdio.h>

int main(void) {
    printf("line1 %d "
           "line2 %s\n", 1, "x");
    return 0;
}
