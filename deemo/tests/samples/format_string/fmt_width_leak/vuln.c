#include <stdio.h>
#include <string.h>
/* FMT-06: %*d 宽度参数泄露 — 用户控制宽度可泄露栈上更多数据 */
int main(int argc, char **argv) {
    char input[256];
    if (argc > 1) {
        strncpy(input, argv[1], 255);
        printf(input, 42);  /* VULNERABLE: %*d 宽度由用户控制 */
    } else {
        printf("safe: value=%d\n", 42);
    }
    return 0;
}
