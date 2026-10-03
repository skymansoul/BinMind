/* 安全: vsnprintf 限长 + 常量格式串. */
#include <stdio.h>
#include <stdarg.h>

void fmt(char *out, size_t n, const char *f, ...) {
    va_list ap;
    va_start(ap, f);
    vsnprintf(out, n, f, ap);
    va_end(ap);
}

int main(void) {
    char buf[32];
    fmt(buf, sizeof(buf), "%d-%s", 3, "x");
    printf("%s\n", buf);
    return 0;
}
