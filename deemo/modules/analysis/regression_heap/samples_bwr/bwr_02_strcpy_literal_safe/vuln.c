/*
 * BWR-02: strcpy 字面量安全
 *
 * 目标 malloc(64), 源为字面量 "short" (6字节).
 * BWR 恢复上界 6 ≤ 可用区 64 → 判定安全, 抑制告警.
 * 基线(跳过无界写)既不误报也不漏报; 增强后保持安静.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    strcpy(p, "short");
    printf("%s\n", p);
    free(p);
    return 0;
}
