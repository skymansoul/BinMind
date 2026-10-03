#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* FMT-08: 条件分支中的格式字符串 — fmt根据条件变为用户输入或常量
 * 检测点: 路径敏感的格式字符串来源分析 */
void process(int debug, const char *user) {
    const char *fmt;
    if (debug) {
        fmt = user;          /* 危险路径: fmt来自用户 */
    } else {
        fmt = "result: %s";  /* 安全路径: fmt是常量 */
    }
    printf(fmt, user);       /* VULNERABLE on debug path */
}
int main(int argc, char **argv) {
    process(argc > 1, argv[1] ? argv[1] : "default");
    return 0;
}
