#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
static void show_it(char *fmt) {
    fprintf(stdout, fmt);
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    show_it(argv[1]);
    return 0;
}
