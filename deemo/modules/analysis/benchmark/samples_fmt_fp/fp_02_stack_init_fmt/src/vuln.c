#include <stdio.h>
int main(int argc, char **argv) {
    char fmt[32] = "val=%d\n";    /* 栈槽常量初始化 */
    printf(fmt, argc);            /* 内容恒定, 非用户可控 */
    return 0;
}
