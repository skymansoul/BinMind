/* fmt_03_sprintf_fmtarg — sprintf 用户格式参数 (VULN)。
 * Expected: VULN */
#include <stdio.h>

int main(int argc, char **argv) {
    char dst[256];
    sprintf(dst, argv[1], 42);    /* fmt = argv[1] */
    puts(dst);
    return 0;
}
