/* heap_realloc_misuse: realloc return value unchecked + used with stale size.
   p = malloc(64); q = realloc(p, 32); memset(p, 0, 64); → use-after-realloc.
   Also tests realloc expansion filter. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = malloc(64);
    if (!p) return 1;
    /* realloc may move the block, p becomes dangling */
    char *q = realloc(p, 32);
    if (!q) { free(p); return 1; }
    memset(p, 0, 64);  /* writes to potentially freed/moved memory */
    free(q);
    return 0;
}
