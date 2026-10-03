/* heap_aliased_ptr: pointer aliasing — p=q after allocation.
   Tests flow-sensitive alias tracking. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = malloc(64);
    if (!p) return 1;
    char *q = p;  /* alias */
    memset(q, 0, 128);  /* overflow via aliased pointer */
    free(p);
    return 0;
}
