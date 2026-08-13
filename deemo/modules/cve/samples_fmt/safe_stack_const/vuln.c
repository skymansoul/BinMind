/* N/A 安全对照: 栈槽常量初始化, 非用户可控. */
#include <stdio.h>

int main(int argc, char **argv) {
    char fmt[] = "val=%d\n";
    printf(fmt, argc);
    return 0;
}
