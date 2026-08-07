/*
 * sample_fmt_09 — 常量格式字符串 (安全)
 * 模式: printf("hello %s", name)  — 格式字符串是字面量
 * 期望: FILTERED 或 NO_CANDIDATE (第一个参数是字面量, 不应匹配)
 */
#include <stdio.h>

int main(void) {
    char name[64] = "world";
    printf("hello %s\n", name);  /* [SAFE] 格式是字面量 */
    return 0;
}
