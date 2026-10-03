#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    unsigned int n = 0x40;
    if (argc > 1) n = (unsigned int)atoi(argv[1]);
    if (n > 128) n = 128;
    char *buf = (char *)malloc(128);
    char *src = (char *)malloc(128);
    if (!buf || !src) return 1;
    memset(src, 'd', 128);
    memcpy(buf, src, n);
    printf("%c\n", buf[0]);
    free(buf); free(src);
    return 0;
}
