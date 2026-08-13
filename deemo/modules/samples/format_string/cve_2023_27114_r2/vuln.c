/*
 * CVE-2023-27114 模式复刻 — radare2 格式化字符串
 * 真实漏洞: radare2 的 r2pipe 对用户可控输入直接格式化输出,
 *           本地代码执行面
 * 触发条件: 管道命令含 % 转换符
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 复刻: 分析输出 */
void r2_output(const char *user_cmd) {
    /* 缺陷: user_cmd 来自交互输入 */
    printf(user_cmd);
}

int main(int argc, char **argv) {
    char cmd[64];
    if (argc > 1) {
        strncpy(cmd, argv[1], sizeof(cmd) - 1);
        cmd[sizeof(cmd) - 1] = 0;
    } else {
        strcpy(cmd, "aaa%s%s%s%s%s");
    }
    r2_output(cmd);
    return 0;
}
