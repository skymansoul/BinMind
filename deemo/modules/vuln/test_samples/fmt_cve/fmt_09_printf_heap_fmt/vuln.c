/* fmt_09_printf_heap_fmt — 堆缓冲用户格式 (VULN)。
 * Expected: VULN */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 2) return 0;
    char *fmt = (char *)malloc(strlen(argv[1]) + 1);
    if (!fmt) return 1;
    strcpy(fmt, argv[1]);
    printf(fmt);                  /* heap format string */
    free(fmt);
    return 0;
}
