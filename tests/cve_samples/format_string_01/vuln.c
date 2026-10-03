/* format_string_01 — printf 直接使用用户输入作为格式化字符串
 * 对应 CWE-134: Use of Externally-Controlled Format String
 * 编译: gcc -o vuln vuln.c
 */
#include <stdio.h>

void log_message(const char *msg) {
    printf(msg);  /* 危险: msg 来自用户输入, 作为格式字符串直接传 printf */
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <msg>\n", argv[0]); return 1; }
    log_message(argv[1]);
    return 0;
}
