#include <stdio.h>
static void log_msg(const char *user) {
    printf("user=%s\n", user);    /* 格式串常量, user 是参数 */
}
int main(int argc, char **argv) {
    log_msg(argc > 1 ? argv[1] : "anon");
    return 0;
}
