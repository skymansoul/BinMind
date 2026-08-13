/*
 * CVE-2021-20226 模式复刻 — io_uring 格式化字符串
 * 真实漏洞: 内核 io_uring 的注册接口对用户可控串直接格式化
 * 触发条件: 注册名含 % 转换符
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 复刻: io_uring 注册调试 */
void io_uring_debug(const char *reg_name) {
    /* 缺陷: reg_name 用户可控 */
    printf(reg_name);
}

int main(int argc, char **argv) {
    char name[64];
    if (argc > 1) {
        strncpy(name, argv[1], sizeof(name) - 1);
        name[sizeof(name) - 1] = 0;
    } else {
        strcpy(name, "uring_%s%s%s%s%s");
    }
    io_uring_debug(name);
    return 0;
}
