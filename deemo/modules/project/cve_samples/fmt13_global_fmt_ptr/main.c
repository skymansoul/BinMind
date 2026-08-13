#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    char *gf = argv[1];
    printf(gf);
    return 0;
}
