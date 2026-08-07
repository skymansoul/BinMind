#include <stdio.h>
#include <stdlib.h>
/* FMT-04: GOT覆写路径 — 结合snprintf和系统调用
 * 可控格式字符串最终影响程序控制流 */
#include <string.h>
void safe_log(const char *user) {
    char buf[256];
    snprintf(buf, sizeof(buf), "user: %s", user);  /* 安全: 固定格式 */
    printf("%s\n", buf);
}
void unsafe_log(const char *user) {
    char fmt[256];
    snprintf(fmt, sizeof(fmt), "user: %s");
    printf(fmt, user);  /* 安全: fmt是固定的 */
    printf(user);       /* VULNERABLE: user作为格式字符串 */
}
int main(int argc, char **argv) {
    if (argc < 2) { safe_log("test"); return 0; }
    unsafe_log(argv[1]);
    return 0;
}
