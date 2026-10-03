/* 包装函数透传常量格式串. */
#include <stdio.h>
#include <stdarg.h>
static void my_log(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}
int main(int argc, char **argv) {
    if (argc < 2) return 0;
    my_log("hello %s\n", argv[1]);
    return 0;
}
