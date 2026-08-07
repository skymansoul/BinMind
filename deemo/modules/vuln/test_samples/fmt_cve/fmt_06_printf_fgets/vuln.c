/* fmt_06_printf_fgets — fgets 缓冲作格式串 (VULN)。
 * Expected: VULN */
#include <stdio.h>

int main(void) {
    char buf[128];
    if (!fgets(buf, sizeof(buf), stdin)) return 0;
    printf(buf);
    return 0;
}
