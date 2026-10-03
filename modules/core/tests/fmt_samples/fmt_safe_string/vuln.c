/*
 * FMT-SAFE-STRING — 安全: %s 传参而非格式串
 * printf("%s", user_input) 用户数据作为参数, 格式串为常量 "%s".
 * 触发: 常规字符串输出.
 */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    /* 安全: 用户数据作为 %s 参数, 格式串为常量 "val=%s" (防 puts 优化) */
    printf("val=%s\n", argv[1]);
    return 0;
}
