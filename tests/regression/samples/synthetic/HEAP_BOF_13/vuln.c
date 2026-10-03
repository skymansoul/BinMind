/* HEAP_BOF_13: reallocarray overflow pattern */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int c, char **v) {
    size_t n = c>1 ? (size_t)atoi(v[1]) : 0x10000000;
    void *b = reallocarray(NULL, n, 16); memcpy(b, v[2]?v[2]:"X", n*16); free(b);
    return 0;
}
