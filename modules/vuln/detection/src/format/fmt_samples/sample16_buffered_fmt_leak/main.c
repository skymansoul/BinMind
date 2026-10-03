#include <stdio.h>

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    /* VULN: format string to stderr via fprintf — dprintf 在 MinGW 不可用.
       漏洞本质不变: 用户控制的格式串传给 fprintf 类函数 */
    fprintf(stderr, argv[1]);
    fprintf(stderr, "\n");
    return 0;
}
