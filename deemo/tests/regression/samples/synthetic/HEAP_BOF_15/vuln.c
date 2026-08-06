/* HEAP_BOF_15: malloc+strcat loop — cumulative heap overflow */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int c, char **v) {
    char *b = malloc(64); b[0] = 0;
    for (int i = 1; i < c; i++) strcat(b, v[i]);
    puts(b); free(b); return 0;
}
