/* fmt_10_printf_scanf — scanf 缓冲作格式串 (VULN)。
 * Expected: VULN */
#include <stdio.h>

int main(void) {
    char buf[128];
    if (scanf("%127s", buf) != 1) return 0;
    printf(buf);
    return 0;
}
