#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
int main(int argc, char **argv) {
    unsigned int a = 0xFFFFFFF0;
    unsigned int b = 0x20;
    unsigned int s = a + b;
    char *p = (char *)malloc(s);
    if (!p) return 1;
    memset(p, 'H', 0x20);
    printf("%c\n", p[0]);
    free(p);
    return 0;
}
