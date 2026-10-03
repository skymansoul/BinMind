/* FMT-TP-01: printf(user_input) — 直接格式化字符串漏洞. */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char buf[128];
    if (argc > 1) {
        strcpy(buf, argv[1]);
    } else {
        strcpy(buf, "hello %x %x %x");
    }
    printf(buf);
    printf("\n");
    return 0;
}
