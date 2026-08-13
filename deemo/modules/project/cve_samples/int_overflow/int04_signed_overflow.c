// int04_signed_overflow: 有符号整数溢出 → 负值绕过边界检查
// 模式: signed int加法溢出 (C未定义行为)
// 预期检测: Mode 4 (SADD_OVF) — 有符号溢出
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    int a = 0x7FFFFFF0;
    a += 0x20;
    printf("%d\n", a);
    return 0;
}
