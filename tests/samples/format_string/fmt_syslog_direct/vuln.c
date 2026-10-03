#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
/* FMT-10: syslog直接使用用户输入 — 系统日志接口的格式字符串漏洞
 * 检测点: 非printf族的格式化函数也需要追踪 */
int main(int argc, char **argv) {
    openlog("fmt_test", LOG_PID, LOG_USER);
    if (argc < 2) {
        syslog(LOG_INFO, "no input provided");
        return 0;
    }
    syslog(LOG_INFO, argv[1]);  /* VULNERABLE: syslog也支持%格式 */
    closelog();
    return 0;
}
