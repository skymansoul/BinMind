/* CVE-2019-11477 TCP 路径: 输入作 printf 格式串. */
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    printf(argv[1]);
    return 0;
}
