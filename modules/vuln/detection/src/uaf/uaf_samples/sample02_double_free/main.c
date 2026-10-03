#include <stdio.h>
#include <stdlib.h>

int main(void) {
    int *p = (int *)malloc(sizeof(int) * 16);
    if (!p) return 1;
    *p = 42;
    free(p);
    /* double free → undefined behavior, UAF after */
    free(p);
    printf("double-freed: %d\n", *p);
    return 0;
}
