#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    char buf[64];
    sprintf(buf, argv[1]);
    printf("%s\n", buf);
    return 0;
}
