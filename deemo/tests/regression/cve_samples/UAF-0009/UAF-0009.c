/* UAF-0009: Use-after-free variant */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
void process9(void) {
    char *p = malloc(208);
    if (p) { strcpy(p, "test"); free(p); }
    /* BUG: p may be used after free */
    if (p) printf("%s", p);
}
int main(void) { process9(); return 0; }
