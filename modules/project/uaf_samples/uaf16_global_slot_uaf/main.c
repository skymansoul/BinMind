#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static char *g_p;

int main(int argc, char **argv) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    g_p = p;
    free(p);
    g_p[0] = 'A';
    printf("%c\n", g_p[0]);
    return 0;
}
