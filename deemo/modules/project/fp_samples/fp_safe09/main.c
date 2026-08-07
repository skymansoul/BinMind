#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    char *buf = (char *)malloc(32);
    if (!buf) return 1;
    char *nbuf = (char *)realloc(buf, 256);
    if (!nbuf) return 1;
    buf = nbuf;
    static char src[256];
    memset(src, 'i', sizeof(src));
    memcpy(buf, src, 256);
    printf("%c\n", buf[0]);
    free(buf);
    return 0;
}
