/**
 * CVE-2014-1475 — OpenSSH PAM conversation passes user input to syslog as format
 * 模式: syslog_fmtstr
 *
 * 样本设计: 精简化复现格式字符串漏洞核心机制.
 * 对静态分析的挑战:
 *   1. 格式字符串来源需追踪 (寄存器/栈/全局/跨函数)
 *   2. 字面量格式字符串应被过滤 (误报控制)
 *   3. 跨函数传播需参数追踪
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdio.h>
#include <stdlib.h>

void v_2014_1475_openssh_log_user(char *user) {
    fprintf(stderr, user);  /* BUG: 模拟syslog(user_input) */
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    printf("=== v_2014_1475_openssh syslog fmt test ===\n");
    v_2014_1475_openssh_log_user(argv[1]);
    return 0;
}

