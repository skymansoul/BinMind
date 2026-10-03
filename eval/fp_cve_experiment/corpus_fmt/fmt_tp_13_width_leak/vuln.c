/* FMT-TP-13: 宽度参数泄露. */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char fmt[64];
    strcpy(fmt, argc > 1 ? argv[1] : "%2$.*3$s");
    printf(fmt, "a", "b", 8);
    return 0;
}
