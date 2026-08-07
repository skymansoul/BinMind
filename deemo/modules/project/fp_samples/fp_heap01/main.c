#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    unsigned int len = 0x400;
    if (argc > 1) len = (unsigned int)atoi(argv[1]);
    char *buf = (char *)malloc(256);
    if (!buf) return 1;
    static char src[1024];
    memset(src, 'B', sizeof(src));
    memcpy(buf, src, len);
    printf("%c\n", buf[0]);
    free(buf);
    return 0;
}
