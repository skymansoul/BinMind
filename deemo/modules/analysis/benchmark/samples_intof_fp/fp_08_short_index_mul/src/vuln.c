#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    unsigned short idx = argc > 1 ? (unsigned short)atoi(argv[1]) : 100;
    char *buf = (char *)malloc((size_t)idx * 16);
    if (!buf) return 1;
    memset(buf, 0, (size_t)idx * 16);
    free(buf);
    return 0;
}
