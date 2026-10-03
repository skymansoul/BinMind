
/* vprintf 格式串来自用户参数. */
#include <stdarg.h>
#include <stdio.h>

static void vemit(char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);        /* 格式串 = 参数 */
    va_end(ap);
}

int main(int argc, char **argv) {
    vemit(argv[1]);
    return 0;
}
