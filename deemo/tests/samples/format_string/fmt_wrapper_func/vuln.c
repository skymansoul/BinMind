#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
/* FMT-06: 包装函数中的格式字符串 — 通过自定义log函数间接调用printf
 * 检测点: 跨函数边界的格式字符串追踪 */
void my_log(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);   /* fmt来自调用者 */
    va_end(ap);
}
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    my_log(argv[1]);    /* VULNERABLE: 用户输入作为fmt传入包装函数 */
    return 0;
}
