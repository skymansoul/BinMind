/* CVE-2015-8612 蓝牙驱动: 包内字符串作 printf 格式串. */
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    printf(argv[1]);
    return 0;
}
