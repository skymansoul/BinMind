// fmt07_printf_constant: printf("%s", user) — 常数字符串格式参数
// 模式: 格式参数是RIP相对地址的常量
// 预期: 不产生finding (SAFE)
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    const char *user = "world";
    if (argc > 1) user = argv[1];

    // 安全: 格式字符串是常量
    printf("Hello, %s!\n", user);
    return 0;
}
