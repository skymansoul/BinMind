/* UAF-0008: Use-after-free variant */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
void process8(void) {
    char *p = malloc(192);
    if (p) { strcpy(p, "test"); free(p); }
    /* BUG: p may be used after free */
    if (p) printf("%s", p);
}
int main(void) { process8(); return 0; }
