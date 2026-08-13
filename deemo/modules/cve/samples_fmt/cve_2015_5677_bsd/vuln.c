/* CVE-2015-5677 BSD 工具: 全局缓冲复制输入后作 printf 格式串. */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char fmt[256];
    if (argc < 2) return 1;
    strcpy(fmt, argv[1]);
    printf(fmt);
    return 0;
}
