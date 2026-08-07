/* FMT-TP-14: print_red(fmt) 包装后透传用户格式串. */
#include <stdio.h>
#include <string.h>

void print_red(const char *fmt) {
    printf(fmt);
}

int main(int argc, char **argv) {
    char fmt[64];
    strcpy(fmt, argc > 1 ? argv[1] : "%s");
    print_red(fmt);
    return 0;
}
