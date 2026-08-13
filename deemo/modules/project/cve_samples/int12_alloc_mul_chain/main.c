#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
int main(int argc, char **argv) {
    unsigned int count = 0x1000000;
    unsigned int sz = count * 0x100;
    char *p = (char *)malloc(sz);
    if (!p) return 1;
    memset(p, 'E', 0x20);
    printf("%c\n", p[0]);
    free(p);
    return 0;
}
