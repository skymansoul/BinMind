/* CWE-134: vsnprintf with user format passed through wrapper */
#include <stdio.h>
#include <stdarg.h>
void log_wrapper(const char *fmt, ...) {
    char buf[512]; va_list ap;
    va_start(ap, fmt); vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    printf("%s", buf);
}
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    log_wrapper(argv[1]); /* format string from user */
    return 0;
}
