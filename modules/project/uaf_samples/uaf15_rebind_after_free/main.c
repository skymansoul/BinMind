#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    char *p = (char *)malloc(32);
    if (!p) return 1;
    free(p);
    p = (char *)malloc(64);
    if (!p) return 1;
    p[0] = 'Z';
    free(p);
    p = NULL;
    if (p) *p = 1;
    printf("%c\n", 'Z');
    return 0;
}
