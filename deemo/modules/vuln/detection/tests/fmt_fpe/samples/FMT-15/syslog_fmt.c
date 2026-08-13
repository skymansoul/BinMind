
/* syslog 格式串来自用户参数. */
#include <stdio.h>

static void syslog_fmt(char *user) {
    printf("[syslog] ");
    printf(user);            /* 格式串 = 用户输入 */
}

int main(int argc, char **argv) {
    syslog_fmt(argv[1]);
    return 0;
}
