#include <stdio.h>
#include <stdarg.h>
#include <string.h>
/* FMT-10: vprintf包装 — 如果包装函数接收用户格式串则危险 */
void log_msg(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);  /* 如果fmt来自用户 → VULNERABLE */
    va_end(ap);
}
int main(int argc, char **argv) {
    const char *fmt = argc > 1 ? argv[1] : "safe: %d\n";
    log_msg(fmt, 42);
    return 0;
}
