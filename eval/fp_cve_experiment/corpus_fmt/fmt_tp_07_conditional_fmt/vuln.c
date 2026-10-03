/* FMT-TP-07: 条件分支选择格式串, 两条路径均来自用户. */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char *fmt;
    char buf1[32], buf2[32];
    strcpy(buf1, argc > 1 ? argv[1] : "%s");
    strcpy(buf2, "%n%n");
    if (argc > 2) {
        fmt = buf1;
    } else {
        fmt = buf2;
    }
    printf(fmt, "x");
    return 0;
}
