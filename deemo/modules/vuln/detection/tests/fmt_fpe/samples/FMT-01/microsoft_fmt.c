
/* 格式串漏洞复现: 用户输入直接作为 printf 格式串. */
#include <stdio.h>

static void handle(char *user) {
    printf(user);            /* 格式串 = 用户输入 */
}

int main(int argc, char **argv) {
    handle(argv[1]);
    return 0;
}
