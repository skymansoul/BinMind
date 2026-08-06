/* UAF-0011: Use-after-free variant */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
void process11(void) {
    char *p = malloc(240);
    if (p) { strcpy(p, "test"); free(p); }
    /* BUG: p may be used after free */
    if (p) printf("%s", p);
}
int main(void) { process11(); return 0; }
