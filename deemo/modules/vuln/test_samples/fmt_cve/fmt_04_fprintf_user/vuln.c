/* fmt_04_fprintf_user — fprintf 用户格式 (VULN)。
 * Expected: VULN */
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc < 2) return 0;
    fprintf(stderr, argv[1]);
    return 0;
}
