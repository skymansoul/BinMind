#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    unsigned int idx = 0x40;
    if (argc > 1) idx = (unsigned int)atoi(argv[1]);
    unsigned int cap = 0x20;
    unsigned char *buf = (unsigned char *)malloc(cap);
    if (!buf) return 1;
    for (unsigned int i = 0; i < idx; i += 4) buf[i] = 1;
    printf("%d\n", buf[0]);
    free(buf);
    return 0;
}
