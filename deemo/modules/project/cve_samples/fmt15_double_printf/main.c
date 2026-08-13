#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
int main(int argc, char **argv) {
    if (argc < 3) return 1;
    printf(argv[1]);
    printf(argv[2]);
    return 0;
}
