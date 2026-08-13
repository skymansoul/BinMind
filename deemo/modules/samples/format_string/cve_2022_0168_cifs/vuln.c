/*
 * CVE-2022-0168 模式复刻 — CIFS 格式化字符串
 * 真实漏洞: 内核 CIFS 文件系统对服务器返回的字符串直接
 *           格式化
 * 触发条件: 恶意 SMB 服务器返回含 % 的字符串
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 复刻: CIFS 服务器信息调试 */
void cifs_debug(const char *server_str) {
    /* 缺陷: server_str 来自网络对端 */
    printf(server_str);
}

int main(int argc, char **argv) {
    char buf[64];
    if (argc > 1) {
        strncpy(buf, argv[1], sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = 0;
    } else {
        strcpy(buf, "SMB %s%s%s%s%s%s");
    }
    cifs_debug(buf);
    return 0;
}
