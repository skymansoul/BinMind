/* UAF-0012: Use-after-free variant */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
void process12(void) {
    char *p = malloc(256);
    if (p) { strcpy(p, "test"); free(p); }
    /* BUG: p may be used after free */
    if (p) printf("%s", p);
}
int main(void) { process12(); return 0; }
