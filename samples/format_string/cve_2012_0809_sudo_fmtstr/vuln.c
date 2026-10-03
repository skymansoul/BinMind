/*
 * cve_2012_0809 — Sudo 格式化字符串 (CWE-134)
 * 模式: argv[0] 作为 fprintf 格式串.
 * 原漏洞: sudo 1.7.x debug 日志中 exec.c 将程序名直接传入日志格式函数.
 * 触发: 攻击者以特殊构造的进程名调用 sudo, 触发 %n 写.
 */
#include <stdio.h>
void debug(const char *prog, const char *msg) {
    fprintf(stderr, prog); /* BUG: prog from argv[0], used as format */
    fprintf(stderr, ": %s\n", msg);
}
int main(int a, char **v) { debug(v[0], "test"); return 0; }
