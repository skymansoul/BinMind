/*
 * 格式化字符串安全对照 A — 静态格式串 + 参数匹配 (TN)
 * 目标: 验证 printf("...", args) 安全模式不误报
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void safe_log(const char *user, int level) {
    /* 安全: 静态格式串, 参数匹配 */
    printf("user=%s level=%d\n", user, level);
}

int main(int argc, char **argv) {
    char name[32];
    strcpy(name, "alice");
    safe_log(name, 3);
    return 0;
}
