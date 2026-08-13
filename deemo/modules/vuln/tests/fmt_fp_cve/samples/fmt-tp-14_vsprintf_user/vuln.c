/* vsprintf 写缓冲, 格式串用户可控. */
#include <stdio.h>
#include <stdarg.h>
static void format(char *out, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsprintf(out, fmt, ap);
    va_end(ap);
}
int main(int argc, char **argv) {
    char out[128];
    if (argc < 2) return 0;
    format(out, argv[1]);
    return 0;
}
