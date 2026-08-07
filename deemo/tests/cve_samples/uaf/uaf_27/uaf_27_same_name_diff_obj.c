/* UAF-27: Safe — different object, same name reused after free (TN) */
#include <stdlib.h>
#include <string.h>

void process(void) {
    char *p = (char *)malloc(64);
    if (!p) return;
    strcpy(p, "first");
    free(p);
    /* SAFE: p reassigned to entirely new allocation */
    p = (char *)malloc(128);
    if (!p) return;
    strcpy(p, "second");
    p[0] = 'y';
    free(p);
}

int main(void) {
    process();
    return 0;
}
