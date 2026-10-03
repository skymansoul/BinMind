/* fmt_11_vprintf_user — vprintf 用户格式 (VULN)。
 * Expected: VULN */
#include <stdio.h>
#include <stdarg.h>

static void p(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}

int main(int argc, char **argv) {
    if (argc < 2) return 0;
    p(argv[1]);
    return 0;
}
