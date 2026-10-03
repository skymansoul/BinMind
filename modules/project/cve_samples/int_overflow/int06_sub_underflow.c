// int06_sub_underflow: 减法下溢 → 无符号回绕
// 模式: umin - val < 0, 回绕至极大值
// 预期检测: Mode 6 (USUB_WRAP) — 减法下溢
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    unsigned int len = 0x20;
    len -= 0x40;
    char *p = (char *)malloc(64);
    char *s = (char *)malloc(64);
    if (!p || !s) return 1;
    memset(s, 'C', 64);
    memcpy(p, s, len);
    printf("%c\n", p[0]);
    free(p); free(s);
    return 0;
}
