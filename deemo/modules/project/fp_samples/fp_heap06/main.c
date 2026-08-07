#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    unsigned int n = 0x100;
    if (argc > 1) n = (unsigned int)atoi(argv[1]);
    char *buf = (char *)malloc(n);
    char *src = (char *)malloc(n);
    if (!buf || !src) return 1;
    memset(src, 'E', n);
    memcpy(buf, src, n + 1);
    printf("%c\n", buf[0]);
    free(buf); free(src);
    return 0;
}
