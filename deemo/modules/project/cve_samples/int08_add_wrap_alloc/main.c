#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
int main(int argc, char **argv) {
    unsigned int sz = 0xFFFFF000;
    sz += 0x1000;
    char *p = (char *)malloc(sz);
    if (!p) return 1;
    memset(p, 'A', 0x20);
    printf("%c\n", p[0]);
    free(p);
    return 0;
}
