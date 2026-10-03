/*
 * CVE-2019-12817 模式复刻 — PPC 格式化字符串
 * 真实漏洞: 内核 powerpc 平台代码对用户可控调试字符串直接
 *           格式化输出
 * 触发条件: 调试接口传入含 %n 的字符串
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 复刻: 调试输出接口 */
void debug_print(const char *user_str) {
    /* 缺陷: user_str 来自调试接口 */
    printf(user_str);
}

int main(int argc, char **argv) {
    char buf[64];
    if (argc > 1) {
        strncpy(buf, argv[1], sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = 0;
    } else {
        strcpy(buf, "%n%n%n%n%n%n");
    }
    debug_print(buf);
    return 0;
}
