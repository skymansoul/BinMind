/*
 * CVE-2021-33034 模式复刻 — USB 格式化字符串
 * 真实漏洞: 内核 USB 驱动的调试路径对设备描述符字符串
 *           直接格式化
 * 触发条件: 恶意 USB 设备的序列号含 %n
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 复刻: USB 设备调试 */
void usb_debug(const char *serial) {
    /* 缺陷: serial 来自设备描述符 */
    printf(serial);
}

int main(int argc, char **argv) {
    char serial[32];
    if (argc > 1) {
        strncpy(serial, argv[1], sizeof(serial) - 1);
        serial[sizeof(serial) - 1] = 0;
    } else {
        strcpy(serial, "%n%n%n%n%n");
    }
    usb_debug(serial);
    return 0;
}
