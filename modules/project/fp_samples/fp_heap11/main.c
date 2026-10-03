#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    unsigned int count = 0x200;
    if (argc > 1) count = (unsigned int)atoi(argv[1]);
    char *buf = (char *)malloc(256);
    if (!buf) return 1;
    for (unsigned int i = 0; i < count; i++) buf[i] = (char)(i + 1);
    printf("%c\n", buf[0]);
    free(buf);
    return 0;
}
