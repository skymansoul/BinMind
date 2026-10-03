/*
 * CVE-2022-32250 模式复刻 — Netfilter 格式化字符串
 * 真实漏洞: 内核 netfilter 的 nftables 错误路径对用户可控
 *           规则名直接格式化
 * 触发条件: 规则名含 %n
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 复刻: nft 规则校验错误日志 */
void nft_error_log(const char *rule_name) {
    /* 缺陷: rule_name 用户可控 */
    printf(rule_name);
}

int main(int argc, char **argv) {
    char name[64];
    if (argc > 1) {
        strncpy(name, argv[1], sizeof(name) - 1);
        name[sizeof(name) - 1] = 0;
    } else {
        strcpy(name, "rule_%n%n%n%n%n");
    }
    nft_error_log(name);
    return 0;
}
