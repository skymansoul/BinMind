
/* fprintf 格式串漏洞复现: 用户输入作格式串. */
#include <stdio.h>

static void log_msg(char *user) {
    fprintf(stderr, user);   /* 用户输入作格式串 */
}

int main(int argc, char **argv) {
    log_msg(argv[1]);
    return 0;
}
