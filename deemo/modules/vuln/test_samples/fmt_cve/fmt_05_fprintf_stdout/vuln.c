/* fmt_05_fprintf_stdout — fprintf(stdout) 用户格式 (VULN)。
 * Expected: VULN */
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc < 2) return 0;
    fprintf(stdout, argv[1]);     /* format = argv[1] */
    return 0;
}
