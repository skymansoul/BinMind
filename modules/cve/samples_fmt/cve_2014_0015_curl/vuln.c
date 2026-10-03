/* CVE-2014-0015 cURL: URL 参数作为 printf 格式串. */
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    printf(argv[1]);
    return 0;
}
