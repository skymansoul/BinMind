#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    unsigned int payload = 0x1000;
    if (argc > 1) payload = (unsigned int)atoi(argv[1]);
    char *buf = (char *)malloc(64);
    char *src = (char *)malloc(payload);
    if (!buf || !src) return 1;
    memset(src, 'C', payload);
    memcpy(buf, src, payload);
    printf("%c\n", buf[0]);
    free(buf); free(src);
    return 0;
}
