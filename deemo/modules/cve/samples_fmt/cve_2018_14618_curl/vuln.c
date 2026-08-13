/* CVE-2018-14618 cURL: netrc 内容经 fprintf(stderr, fmt) 使用. */
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    fprintf(stderr, argv[1]);
    return 0;
}
