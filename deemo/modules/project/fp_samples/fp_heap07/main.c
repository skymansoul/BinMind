#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    unsigned int n = 0x40000000;
    if (argc > 1) n = (unsigned int)atoi(argv[1]);
    unsigned int alloc_size = n * 4;
    char *buf = (char *)malloc(alloc_size);
    if (!buf) return 1;
    memset(buf, 'F', (size_t)n * 4);
    printf("%c\n", buf[0]);
    free(buf);
    return 0;
}
