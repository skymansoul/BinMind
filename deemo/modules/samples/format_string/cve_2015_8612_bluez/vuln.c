/*
 * CVE-2015-8612 模式复刻 — BlueZ 格式化字符串漏洞
 * 真实漏洞: BlueZ 的 btauditd 日志函数将用户可控数据直接
 *           作为 printf 格式串, 可拒绝服务/泄露信息
 * 触发条件: 蓝牙事件名称含 % 字符
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 复刻: 外部蓝牙事件名直接作为格式串 */
void log_bluetooth_event(const char *event_name) {
    /* 缺陷: event_name 用户可控, 直接作格式串 */
    printf(event_name);
}

int main(int argc, char **argv) {
    char event[64];
    /* 外部输入: 模拟蓝牙 HCI 事件名 */
    if (argc > 1) {
        strncpy(event, argv[1], sizeof(event) - 1);
        event[sizeof(event) - 1] = 0;
    } else {
        strcpy(event, "%s%s%s%s%s%s%s%s%s%s%n");
    }
    log_bluetooth_event(event);
    return 0;
}
