#include <stdio.h>
#include <stdlib.h>

/* 模拟 syslog 的格式串漏洞 — MinGW 无 <syslog.h>, 用 fprintf 等价模式.
   VULN: user input as format string to logging function */
void fake_syslog(int prio, const char *fmt, ...) {
    /* 模拟: 实际代码中 syslog 将 fmt 传给 vsyslog */
    fprintf(stderr, "[LOG:%d] ", prio);
    fprintf(stderr, fmt);  /* VULN: fmt 直接被传给 fprintf */
    fprintf(stderr, "\n");
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    /* VULN: 用户输入作为格式化串传入日志函数 */
    fake_syslog(3, argv[1]);
    return 0;
}
