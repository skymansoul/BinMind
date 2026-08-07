#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    strcpy(p, "conditional");
    if (argc > 1) {
        free(p);  /* free only when argv present */
    }
    /* UAF: unconditional use after conditional free */
    p[0] = 'C';
    printf("conditional: %s\n", p);
    return 0;
}
