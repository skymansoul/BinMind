
/* 格式串变量被用户输入覆盖后使用. */
#include <stdio.h>

int main(int argc, char **argv) {
    char *fmt = "fixed";
    if (argc > 1) fmt = argv[1];  /* 覆盖为用户输入 */
    printf(fmt);
    return 0;
}
