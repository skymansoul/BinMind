/*
 * CVE-2020-25656 模式复刻 — VT 控制台格式化字符串
 * 真实漏洞: 内核虚拟终端对用户可控调试串直接格式化
 * 触发条件: 终端输入含 %n
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 复刻: 终端驱动调试输出 */
void vt_debug(const char *input) {
    /* 缺陷: input 来自终端输入 */
    printf(input);
}

int main(int argc, char **argv) {
    char buf[64];
    if (argc > 1) {
        strncpy(buf, argv[1], sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = 0;
    } else {
        strcpy(buf, "ESC[%n%n%n%n");
    }
    vt_debug(buf);
    return 0;
}
