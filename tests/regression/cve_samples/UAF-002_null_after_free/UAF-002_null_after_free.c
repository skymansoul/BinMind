/* UAF-002: Safe pattern — free then NULL assignment (not a UAF) */
#include <stdlib.h>
#include <stdio.h>
void process(void) {
    char *buf = malloc(64);
    free(buf);
    buf = NULL;
    printf("%s", buf); /* NULL deref, not UAF */
}
int main(void) { process(); return 0; }
