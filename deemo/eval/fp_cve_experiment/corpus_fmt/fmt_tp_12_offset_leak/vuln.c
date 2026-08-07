/* FMT-TP-12: 用户格式串含位置参数, 用于栈泄露. */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char fmt[64];
    strcpy(fmt, argc > 1 ? argv[1] : "%%7$llx");
    printf(fmt);
    return 0;
}
