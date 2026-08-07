#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    unsigned int n = 0x40;
    if (argc > 1) n = (unsigned int)atoi(argv[1]);
    char *buf = (char *)malloc(n);
    char *src = (char *)malloc(n);
    if (!buf || !src) return 1;
    memset(src, 'a', n);
    memcpy(buf, src, n);
    printf("%c\n", buf[0]);
    free(buf); free(src);
    return 0;
}
