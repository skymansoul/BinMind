/* UAF-0014: Use-after-free variant */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
void process14(void) {
    char *p = malloc(288);
    if (p) { strcpy(p, "test"); free(p); }
    /* BUG: p may be used after free */
    if (p) printf("%s", p);
}
int main(void) { process14(); return 0; }
