/*
 * sample_fmt_15 — syslog 格式字符串注入 (CWE-134 日志场景)
 * 模式: recv → syslog(LOG_ERR, user_input)  — syslog 作为 sink
 * 期望: CONFIRMED (置信度 ≥ 0.65)
 *
 * 关键点: syslog() 的第一个参数若包含用户数据且无 %s 包装,
 *         同样构成 CWE-134. 此场景在 CVE-2022-30284 / CVE-2023-22809 中出现.
 *         检测器应覆盖 syslog / vsyslog / __syslog_chk
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#define MAX_INPUT 512

// 模拟接收网络数据
ssize_t recv_data(int fd, char *buf, size_t len) {
    // 桩函数: 实际场景中使用 recv() / read()
    (void)fd;
    const char *test = "User %s login failed: %n";  // 格式字符串攻击负载
    strncpy(buf, test, len - 1);
    buf[len - 1] = '\0';
    return (ssize_t)strlen(buf);
}

int main(int argc, char *argv[]) {
    char buffer[MAX_INPUT];
    int sock = 0;  // 模拟 socket fd

    openlog("fmt_15_test", LOG_PID | LOG_CONS, LOG_USER);

    // 接收网络数据
    ssize_t n = recv_data(sock, buffer, sizeof(buffer));
    if (n <= 0) {
        closelog();
        return 1;
    }

    // CWE-134: syslog 的第一个参数是用户可控数据
    // 攻击者注入 %n → 写入任意地址; %s → 信息泄漏
    syslog(LOG_ERR, buffer);

    // 对比: 安全模式 — 固定格式字符串 + 用户数据作为参数
    syslog(LOG_INFO, "Received message: %s", buffer);  // 安全

    closelog();

    // 同时也存在 printf 直接调用 (双重确认)
    printf("Logged: ");
    printf(buffer);  // CWE-134: 第二个 printf sink
    printf("\n");

    return 0;
}
