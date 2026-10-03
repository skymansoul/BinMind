/*
 * CVE-2019-19043 模式复刻 — iwlwifi 格式化字符串
 * 真实漏洞: 内核 iwlwifi 无线驱动将用户可控的 SSID/调试串
 *           直接格式化, 本地可触发
 * 触发条件: 恶意 SSID 含 % 转换符
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 复刻: 无线调试日志 */
void iwl_debug_log(const char *ssid) {
    /* 缺陷: ssid 来自无线帧, 用户可控 */
    printf(ssid);
}

int main(int argc, char **argv) {
    char ssid[32];
    if (argc > 1) {
        strncpy(ssid, argv[1], sizeof(ssid) - 1);
        ssid[sizeof(ssid) - 1] = 0;
    } else {
        strcpy(ssid, "%p%p%p%p%p%p");
    }
    iwl_debug_log(ssid);
    return 0;
}
