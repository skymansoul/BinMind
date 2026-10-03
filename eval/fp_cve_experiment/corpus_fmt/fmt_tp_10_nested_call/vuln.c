/* FMT-TP-10: 用户输入经计算进入格式串. */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char fmt[256];
    const char *src = argc > 1 ? argv[1] : "%s%s%s";
    size_t n = strlen(src);
    memcpy(fmt, src, n);
    fmt[n] = 0;
    printf(fmt, "a", "b", "c");
    return 0;
}
