/* 用户输入经 fprintf 到 stderr. */
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    char buf[64];
    if (argc < 2) return 0;
    strncpy(buf, argv[1], 63);
    buf[63] = 0;
    fprintf(stderr, buf);
    return 0;
}
