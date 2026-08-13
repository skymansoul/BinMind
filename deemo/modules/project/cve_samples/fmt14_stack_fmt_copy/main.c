#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    char fmt[32];
    strncpy(fmt, argv[1], sizeof(fmt) - 1);
    fmt[sizeof(fmt) - 1] = 0;
    printf(fmt);
    return 0;
}
