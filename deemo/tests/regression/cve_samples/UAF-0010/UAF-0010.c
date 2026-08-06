/* UAF-0010: Use-after-free variant */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
void process10(void) {
    char *p = malloc(224);
    if (p) { strcpy(p, "test"); free(p); }
    /* BUG: p may be used after free */
    if (p) printf("%s", p);
}
int main(void) { process10(); return 0; }
