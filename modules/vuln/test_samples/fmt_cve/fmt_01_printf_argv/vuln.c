/* fmt_01_printf_argv — argv 格式串 (VULN)。
 * Expected: VULN */
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc < 2) return 0;
    printf(argv[1]);              /* format string from argv */
    return 0;
}
