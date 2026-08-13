
/* fprintf(stdout) 格式串漏洞复现: 用户输入作格式串. */
#include <stdio.h>

static void send(int fd, char *user) {
    fprintf(stdout, user);   /* 格式串 = 用户输入 */
}

int main(int argc, char **argv) {
    send(1, argv[1]);
    return 0;
}
