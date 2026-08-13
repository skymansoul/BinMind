#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    unsigned int base = 0xFFFFFFF0;
    unsigned int o = base + 0x20;
    char *p = (char *)malloc(o);
    if (!p) return 1;
    memset(p, 'F', 0x20);
    printf("%c\n", p[0]);
    free(p);
    return 0;
}
