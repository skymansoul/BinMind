#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    unsigned int n = 0x40000000;
    unsigned int sz = n * 4;
    char *p = (char *)malloc(sz);
    if (!p) return 1;
    memset(p, 'G', (size_t)n * 4);
    printf("%c\n", p[0]);
    free(p);
    return 0;
}
