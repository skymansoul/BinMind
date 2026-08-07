#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    unsigned int n = 0x40;
    if (argc > 1) n = (unsigned int)atoi(argv[1]);
    char *buf = (char *)malloc(n);
    if (!buf) return 1;
    for (unsigned int i = 0; i < n; i++) buf[i] = 'b';
    printf("%c\n", buf[0]);
    free(buf);
    return 0;
}
