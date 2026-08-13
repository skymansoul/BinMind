
/* 格式串经 strcpy 拼接后使用 — 用户可控. */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char fmt[128];
    strcpy(fmt, argv[1]);    /* 用户输入入缓冲 */
    printf(fmt);             /* 格式串 = 用户输入 */
    return 0;
}
