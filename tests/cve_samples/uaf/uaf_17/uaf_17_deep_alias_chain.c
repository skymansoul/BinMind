/* UAF-17: Deep alias chain (3 hops) — free via intermediate, use via end of chain (TP) */
#include <stdlib.h>
#include <string.h>

void process(void) {
    char *a = (char *)malloc(64);
    if (!a) return;
    char *b = a;
    char *c = b;
    char *d = c;
    /* free via b */
    free(b);
    /* BUG: use via d — 3-hop alias chain */
    d[0] = 'x';
}

int main(void) {
    process();
    return 0;
}
