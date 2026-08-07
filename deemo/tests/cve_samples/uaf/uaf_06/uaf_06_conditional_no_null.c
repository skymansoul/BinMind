/* UAF-06: Conditional free without NULL — use after conditional free (TP) */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void process(int should_free) {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    strcpy(buf, "test data");

    if (should_free) {
        free(buf);
        /* BUG: buf NOT set to NULL after free */
    }
    /* UAF on the should_free path: buf is dangling */
    /* On the !should_free path: buf is still valid */
    printf("%s\n", buf);
}

int main(void) {
    process(1);  /* triggers UAF */
    return 0;
}
