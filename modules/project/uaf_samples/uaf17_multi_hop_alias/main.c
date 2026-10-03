#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    char *q = p;
    char *r = q;
    free(p);
    r[0] = 'B';
    printf("%c\n", r[0]);
    return 0;
}
