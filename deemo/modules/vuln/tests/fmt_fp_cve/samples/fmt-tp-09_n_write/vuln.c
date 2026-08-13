/* 用户可控格式串含 %n, 存在写内存面. */
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    char buf[128];
    int written = 0;
    if (argc < 2) return 0;
    strncpy(buf, argv[1], 127);
    buf[127] = 0;
    printf(buf, &written);
    return 0;
}
