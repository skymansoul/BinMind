/* CVE-2021-3156 — sudo Baron Samedit (heap overflow)
 * 漏洞: sudoers.c set_cmnd() 中命令行参数复制时越界写
 * 演示: 简化版unchecked strcpy
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void set_command(char *user_args, int user_len) {
    char *buf = (char *)malloc(64);
    /* BUG: user_len可能 > 64, 但未检查 */
    memcpy(buf, user_args, user_len); /* HEAP OVERFLOW */
    printf("cmd: %s\n", buf);
    free(buf);
}
int main(int argc, char **argv) {
    char input[256];
    if (argc > 1) {
        strcpy(input, argv[1]);
        set_command(input, strlen(input));
    }
    return 0;
}
