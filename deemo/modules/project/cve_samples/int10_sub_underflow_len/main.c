#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
int main(int argc, char **argv) {
    unsigned int len = 0;
    len -= 1;
    char *p = (char *)malloc(64);
    char *s = (char *)malloc(64);
    if (!p || !s) return 1;
    memset(s, 'C', 64);
    memcpy(p, s, len);
    printf("%c\n", p[0]);
    free(p); free(s);
    return 0;
}
