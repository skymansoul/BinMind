/* fmt_02_printf_gets — gets 缓冲作格式串 (VULN)。
 * Expected: VULN */
#include <stdio.h>

int main(void) {
    char buf[128];
    gets(buf);
    printf(buf);                  /* user-controlled format */
    return 0;
}
