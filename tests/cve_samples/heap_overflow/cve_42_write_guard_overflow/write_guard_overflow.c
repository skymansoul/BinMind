#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * CVE-42: write_guard溢出 — 缺少边界保护导致越界写入
 *
 * 模式: malloc(64); memcpy(buf+60, src, 16);
 * write_end=60+16=76 > usable(64)=72 → OVERFLOW
 */
int main() {
    int offset = 60;
    char *buf = (char *)malloc(64);
    if (!buf) return 1;
    char src[16] = "AAAAAAAAAAAAAAA";
    memcpy(buf + offset, src, 16);
    free(buf);
    return 0;
}
