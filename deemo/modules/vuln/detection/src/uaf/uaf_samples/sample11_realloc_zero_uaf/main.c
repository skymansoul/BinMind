#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *p = (char *)malloc(128);
    if (!p) return 1;
    strcpy(p, "zero_realloc");
    /* realloc(p, 0) — implementation-defined: may free or return NULL */
    char *q = (char *)realloc(p, 0);
    if (q == NULL) {
        /* UAF: original p may have been freed */
        p[0] = 'Z';
        printf("zero-realloc uaf: %c\n", p[0]);
    }
    return 0;
}
