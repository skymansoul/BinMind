/* 格式化字符串漏洞: printf(user_input) 无格式串参数 */
#include <stdio.h>
int main(int argc, char **argv) {
    char buf[256];
    if (argc > 1) {
        snprintf(buf, sizeof(buf), argv[1]); /* FMT STRING from argv */
        printf("%s", buf);
    }
    return 0;
}
