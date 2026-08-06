/* HEAP_BOF_12: calloc overflow — nmemb*size unchecked */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int c, char **v) {
    size_t n = c>1 ? (size_t)atoi(v[1]) : 0x40000000;
    char *b = calloc(n, 4); memcpy(b, v[2]?v[2]:"X", n*4); free(b);
    return 0;
}
