/* FMT TP sample */
#include <stdio.h>
#include <stdarg.h>
static void do_log(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}
int main(int argc, char **argv) {
    if (argc > 1) { do_log(argv[1]); }
    return 0;
}
