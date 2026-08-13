/*
 * CVE-2017-1000369 模式复刻 — exim 格式化字符串
 * 真实漏洞: Exim 邮件服务器在特定配置下将用户输入直接传入
 *           snprintf/printf 系列, 可提权 (CVE-2017-1000369)
 * 触发条件: SMTP 命令参数含 %n
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 复刻: 邮件头解析后日志打印用户控制串 */
void log_message(const char *header_value) {
    /* 缺陷: header_value 用户可控 */
    printf(header_value);
}

int main(int argc, char **argv) {
    char header[128];
    /* 外部输入: SMTP Received 头 */
    if (argc > 1) {
        strncpy(header, argv[1], sizeof(header) - 1);
        header[sizeof(header) - 1] = 0;
    } else {
        strcpy(header, "Received: from %n%n%n%n attacker");
    }
    log_message(header);
    return 0;
}
