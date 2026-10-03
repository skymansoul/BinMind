#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    static char fdata[0x1000];
    memset(fdata, 'H', sizeof(fdata));
    char *buf = (char *)malloc(64);
    if (!buf) return 1;
    size_t fsize = 0x1000;
    if (argc > 1) fsize = (size_t)atoi(argv[1]);
    memcpy(buf, fdata, fsize);
    printf("%c\n", buf[0]);
    free(buf);
    return 0;
}
