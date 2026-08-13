#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
int main(int argc, char **argv) {
    char *p = (char *)malloc(64);
    char *s = (char *)malloc(64);
    if (!p || !s) return 1;
    unsigned int off = 0xFFFFFFFF;
    memset(s, 'F', 64);
    memcpy(p + off, s, 0x20);
    printf("%c\n", p[0]);
    free(p); free(s);
    return 0;
}
