/*
 * sample_fmt_05 — syslog(user_input)
 * 模式: fgets → syslog(user_input)
 * 期望: CONFIRMED
 */
#include <stdio.h>
#include <syslog.h>

int main(void) {
    char buf[256];
    if (fgets(buf, sizeof(buf), stdin) == NULL)
        return 1;
    syslog(LOG_INFO, buf);  /* [VULN] */
    return 0;
}
