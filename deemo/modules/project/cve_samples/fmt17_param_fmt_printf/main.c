#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
static void log_it(char *fmt) {
    printf(fmt);
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    log_it(argv[1]);
    return 0;
}
