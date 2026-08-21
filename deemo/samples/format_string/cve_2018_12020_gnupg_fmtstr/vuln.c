/*
 * cve_2018_12020 — GnuPG 格式化字符串 (CWE-134)
 * 模式: snprintf(..., fn) — 文件名作格式串.
 * 原漏洞: keyboxd/gpg 处理特定授权文件时, 用文件名直接作 snprintf 格式串.
 */
#include <stdio.h>
#include <string.h>
void print_status(const char *fn, int st) {
    char line[512];
    snprintf(line, sizeof(line), fn, st); /* BUG: filename as format */
    printf("%s", line);
}
int main(int a, char **v) { if(a<2) return 1;
    print_status(v[1], 0); return 0; }
