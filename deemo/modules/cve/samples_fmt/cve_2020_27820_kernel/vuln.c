/* CVE-2020-27820 内核: 用户可控串作 snprintf 格式串. */
#include <stdio.h>

int main(int argc, char **argv) {
    char dst[128];
    if (argc < 2) return 1;
    snprintf(dst, sizeof(dst), argv[1]);
    puts(dst);
    return 0;
}
