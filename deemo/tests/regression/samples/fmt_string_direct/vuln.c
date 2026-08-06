#include <stdio.h>
/* CVE-2016-4971 模式: 直接格式化字符串漏洞 */
void log_message(char *msg) {
    /* BUG: msg直接作为format参数, 若msg含%n可导致任意写 */
    printf(msg);
}
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    log_message(argv[1]);
    return 0;
}
