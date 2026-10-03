/* CVE-2012-0809 sudo 格式化字符串: 将 argv 直接作为 printf 格式串. */
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    printf(argv[1]);
    return 0;
}
