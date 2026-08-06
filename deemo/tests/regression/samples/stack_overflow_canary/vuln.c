#include <stdio.h>
#include <string.h>
/* 带canary的栈溢出——测试canary检测能力 */
void safe_copy(char *src) {
    char buf[32];
    /* BUG: 溢出, 但有__stack_chk_fail保护 */
    strcpy(buf, src);
    printf("%s
", buf);
}
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    safe_copy(argv[1]);
    return 0;
}
