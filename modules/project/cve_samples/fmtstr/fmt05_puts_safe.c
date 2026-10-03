// fmt05_puts_safe: puts/puts调用 — 不解析格式字符串
// 模式: puts(user_input) — 无格式字符串风险
// 预期: 不产生finding (SAFE)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    const char *msg = "Hello World";
    if (argc > 1) msg = argv[1];
    // 安全: puts不解析格式字符串
    fputs(msg, stdout);
    fputs("\n", stdout);
    return 0;
}
