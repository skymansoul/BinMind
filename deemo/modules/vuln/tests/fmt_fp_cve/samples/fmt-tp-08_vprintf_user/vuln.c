/* 用户输入直接进 vprintf. */
#include <stdio.h>
#include <stdarg.h>
static void emit(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}
int main(int argc, char **argv) {
    if (argc < 2) return 0;
    emit(argv[1]);
    return 0;
}
