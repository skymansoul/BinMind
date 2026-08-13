/*
 * 格式化字符串安全对照 C — 长度受限格式化 (TN)
 * 目标: 验证 snprintf 带上限 + 静态格式串不误报
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void safe_snprintf(char *out, size_t cap, const char *user) {
    /* 安全: snprintf 上限 + 静态格式串 */
    snprintf(out, cap, "user: %s", user);
}

int main(int argc, char **argv) {
    char buf[64];
    safe_snprintf(buf, sizeof(buf), "bob");
    printf("%s\n", buf);
    return 0;
}
