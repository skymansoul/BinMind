/* N/A 安全对照: 指针指向 .rdata 字面量, 非用户可控. */
#include <stdio.h>

int main(int argc, char **argv) {
    const char *fmt = "%d\n";
    printf(fmt, argc);
    return 0;
}
