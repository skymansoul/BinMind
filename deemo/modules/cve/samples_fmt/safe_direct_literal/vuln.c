/* N/A 安全对照: 直接字面量格式串. */
#include <stdio.h>

int main(int argc, char **argv) {
    printf("%s\n", argc > 1 ? argv[1] : "none");
    return 0;
}
