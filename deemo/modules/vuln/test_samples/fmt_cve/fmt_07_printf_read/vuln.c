/* fmt_07_printf_read — read 缓冲作格式串 (VULN)。
 * Expected: VULN */
#include <stdio.h>
#include <unistd.h>

int main(void) {
    char buf[256];
    int n = read(0, buf, sizeof(buf) - 1);
    if (n <= 0) return 0;
    buf[n] = 0;
    printf(buf);
    return 0;
}
