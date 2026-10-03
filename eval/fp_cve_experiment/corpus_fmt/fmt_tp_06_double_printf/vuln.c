/* FMT-TP-06: 两次 printf 同一用户格式串. */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char fmt[64];
    strcpy(fmt, argc > 1 ? argv[1] : "%x%x");
    printf(fmt);
    printf(fmt);
    return 0;
}
