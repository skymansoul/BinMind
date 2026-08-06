/* UAF-0013: Use-after-free variant */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
void process13(void) {
    char *p = malloc(272);
    if (p) { strcpy(p, "test"); free(p); }
    /* BUG: p may be used after free */
    if (p) printf("%s", p);
}
int main(void) { process13(); return 0; }
