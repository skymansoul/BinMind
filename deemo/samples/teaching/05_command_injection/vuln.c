/*
 * 教学样本 #5: 命令注入 (system 调用)
 *
 * 漏洞: 用户输入直接传递给 system() 未做过滤。
 * 编译: gcc -o vuln vuln.c
 *
 * 利用思路: 输入 "; cat /etc/passwd" 或 "`id`" 执行任意命令
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void ping_host(const char *host) {
    char cmd[256];
    /* 漏洞: 直接拼接用户输入到 shell 命令 */
    snprintf(cmd, sizeof(cmd), "ping -c 1 %s", host);
    printf("executing: %s\n", cmd);
    system(cmd);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("usage: %s <host>\n", argv[0]);
        return 1;
    }
    ping_host(argv[1]);
    return 0;
}
