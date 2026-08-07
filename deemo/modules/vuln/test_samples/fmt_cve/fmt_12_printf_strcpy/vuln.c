/* fmt_12_printf_strcpy — strcpy 复制的用户格式 (VULN)。
 * Expected: VULN */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 2) return 0;
    char buf[256];
    strcpy(buf, argv[1]);
    printf(buf);
    return 0;
}
