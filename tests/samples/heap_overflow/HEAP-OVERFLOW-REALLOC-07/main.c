/* HEAP-OVERFLOW-REALLOC-07: realloc shrinks buffer then write at old size.
   p=malloc(256); p=realloc(p,64); memset(p,0,256) → overflow.
   Tests realloc-aware allocation history tracking. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = malloc(256);
    if (!p) return 1;
    p = realloc(p, 64);
    if (!p) return 1;
    memset(p, 0, 256);  /* overflow: buffer now only 64 bytes */
    free(p);
    return 0;
}
