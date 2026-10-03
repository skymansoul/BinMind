/*
 * FMT-VULN-USER — 用户可控格式串 (CWE-134)
 * printf(user_input) 直接把外部参数当格式串.
 * 触发: main 的 argv[1] 原样传入 printf.
 */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    char user_input[128];
    strncpy(user_input, argv[1], sizeof(user_input) - 1);
    user_input[127] = '\0';
    /* 漏洞: 用户输入作为格式串 */
    printf(user_input);
    printf("\n");
    return 0;
}
