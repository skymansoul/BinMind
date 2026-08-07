#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    unsigned int len = 0x1000;
    if (argc > 1) len = (unsigned int)atoi(argv[1]);
    char *buf = (char *)malloc(0x400);
    char *data = (char *)malloc(len);
    if (!buf || !data) return 1;
    memset(data, 'K', len);
    memcpy(buf, data, len);
    printf("%c\n", buf[0]);
    free(buf); free(data);
    return 0;
}
