#include <stdio.h>
#include <stdlib.h>

int main(void) {
    int *orig = (int *)malloc(sizeof(int) * 8);
    int *alias = orig;  /* alias points to same block */
    if (!orig) return 1;
    orig[0] = 100;
    free(orig);
    /* UAF: alias still points to freed memory */
    alias[0] = 200;
    printf("alias[0] = %d\n", alias[0]);
    return 0;
}
