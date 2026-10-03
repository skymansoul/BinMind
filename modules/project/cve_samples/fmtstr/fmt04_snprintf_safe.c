// fmt04_snprintf_safe: snprintf带常量格式 — 安全
// 模式: snprintf(buf, n, "constant fmt %s", user) — 格式是常量
// 预期: 不产生finding (SAFE)
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    char buf[512];
    const char *user = "default";
    if (argc > 1) user = argv[1];

    // 安全: 格式字符串是常量, user是参数
    snprintf(buf, sizeof(buf), "User input: %s", user);
    printf("%s\n", buf);
    return 0;
}
