#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *p = (char *)malloc(16);
    if (!p) return 1;
    strcpy(p, "hello");
    /* safe: use returned pointer from realloc */
    char *q = (char *)realloc(p, 128);
    if (!q) { free(p); return 1; }
    strcat(q, " world");
    printf("realloc safe: %s\n", q);
    free(q);
    return 0;
}
