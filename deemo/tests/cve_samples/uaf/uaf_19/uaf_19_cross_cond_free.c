/* UAF-19: Cross-function conditional free — callee frees conditionally but caller doesn't check (TP) */
#include <stdlib.h>
#include <string.h>

void maybe_free(char *ptr, int should_free) {
    if (should_free) {
        free(ptr);
    }
}

void process(void) {
    char *buf = (char *)malloc(128);
    if (!buf) return;
    maybe_free(buf, 1);
    /* BUG: may be freed inside maybe_free, caller doesn't check */
    buf[0] = 'x';
}

int main(void) {
    process();
    return 0;
}
