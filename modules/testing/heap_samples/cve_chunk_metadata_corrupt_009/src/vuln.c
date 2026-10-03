/* Overflow into next chunk's metadata */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    char *a = (char *)malloc(128);
    char *b = (char *)malloc(128);
    char *c = (char *)malloc(128);
    if (!a || !b || !c) return 1;
    memset(a, 'A', 128); memset(b, 'B', 128); memset(c, 'C', 128);
    size_t off = argc > 1 ? (size_t)atoi(argv[1]) : 200;
    if (off < 512) a[off] = 'X';  /* BUG: overflows into b */
    printf("[*] a=%p b=%p c=%p off=%zu\n", (void*)a, (void*)b, (void*)c, off);
    free(a); free(b); free(c);
    return 0;
}
