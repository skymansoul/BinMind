#include <stdio.h>
#include <string.h>
/* CVE-2017-1000253 模式: 栈缓冲区溢出 */
void copy_input(char *src) {
    char buf[64];
    /* BUG: 未检查长度, src>64即栈溢出 */
    strcpy(buf, src);
    printf("copied: %s
", buf);
}
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    copy_input(argv[1]);
    return 0;
}
