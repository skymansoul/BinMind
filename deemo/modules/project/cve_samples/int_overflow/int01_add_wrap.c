// int01_add_wrap: 无符号加法回绕 → 边界检查被绕过
// 模式: 用户输入size, 加上固定偏移后回绕, 绕过边界检查
// 预期检测: Mode 1 (UADD_WRAP) — add回绕
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    unsigned int a = 0xFFFFFFF0;
    a += 0x20;
    printf("%u\n", a);
    return 0;
}
