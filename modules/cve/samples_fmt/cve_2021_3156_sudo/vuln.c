/* CVE-2021-3156 sudo: 命令行参数作 printf 格式串. */
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    printf(argv[1]);
    return 0;
}
