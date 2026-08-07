/* UAF TN (safe) sample */
#include <stdlib.h>
#include <stdio.h>
int main(void) {
    void *p = malloc(16);
    if (!p) return -1;
    free(p);
    unsigned long addr = (unsigned long)p;
    printf("%lu", addr);
    return 0;
}
