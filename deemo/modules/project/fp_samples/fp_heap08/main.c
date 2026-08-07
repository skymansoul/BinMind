#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    unsigned int len = 0x100;
    if (argc > 1) len = (unsigned int)atoi(argv[1]);
    char *buf = (char *)malloc(len - 1);
    char *src = (char *)malloc(len);
    if (!buf || !src) return 1;
    memset(src, 'G', len);
    memcpy(buf, src, len);
    printf("%c\n", buf[0]);
    free(buf); free(src);
    return 0;
}
