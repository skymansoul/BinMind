/* fmt_08_snprintf_fmtarg — snprintf 用户格式 (VULN)。
 * Expected: VULN */
#include <stdio.h>

int main(int argc, char **argv) {
    char dst[256];
    snprintf(dst, sizeof(dst), argv[1], 7);
    puts(dst);
    return 0;
}
