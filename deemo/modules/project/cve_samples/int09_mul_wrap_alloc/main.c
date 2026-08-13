#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
int main(int argc, char **argv) {
    unsigned int n = 0x40000000;
    n *= 4;
    char *p = (char *)malloc(n);
    if (!p) return 1;
    memset(p, 'B', 0x20);
    printf("%c\n", p[0]);
    free(p);
    return 0;
}
