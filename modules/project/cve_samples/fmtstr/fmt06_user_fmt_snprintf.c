// fmt06_user_fmt_snprintf: snprintf格式参数来自输入 — 格式化字符串漏洞
// 模式: snprintf(buf, n, user_input, args...) — 格式参数非常量
// 预期检测: REGISTER_FMT / DIRECT_USER_FMT — HIGH/MEDIUM
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 模拟日志函数: 格式字符串来自外部
void log_message(const char *fmt, const char *detail) {
    char buf[512];
    // 漏洞: fmt来自用户, 若包含%n可写任意内存
    snprintf(buf, sizeof(buf), fmt, detail);
    fprintf(stderr, "%s\n", buf);
}

int main(int argc, char **argv) {
    const char *fmt = "Info: %s";
    if (argc > 1) fmt = argv[1];

    log_message(fmt, "test detail");
    return 0;
}
