/*
 * cve_2015_5677 — FreeBSD bsnmpd 格式化字符串 (CWE-134)
 * 模式: snprintf(..., input) — 用户输入直接作格式串.
 * 原漏洞: bsnmpd GETBULK 请求中字段名被作为 snprintf 格式串使用.
 */
#include <stdio.h>
void log_event(const char *input) {
    char buf[256];
    snprintf(buf, sizeof(buf), input); /* BUG: input used as format string */
    printf("LOG: %s", buf);
}
int main(int a, char **v) { if(a<2) return 1;
    log_event(v[1]); return 0; }
