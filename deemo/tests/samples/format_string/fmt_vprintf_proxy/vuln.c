#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
/* FMT-11: vprintf代理 — 变参宏/函数传递格式字符串
 * 攻击者控制最外层fmt会传播到所有内层变参函数 */
void log_va(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}
void log_info(const char *msg) {
    log_va(msg);  /* 间接传递格式字符串 */
}
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    log_info(argv[1]);  /* VULNERABLE: 三层间接调用 */
    return 0;
}
