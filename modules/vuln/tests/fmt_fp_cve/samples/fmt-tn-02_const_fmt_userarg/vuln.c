/* 格式串常量, 用户数据仅作参数. */
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc < 2) return 0;
    printf("%s\n", argv[1]);
    return 0;
}
