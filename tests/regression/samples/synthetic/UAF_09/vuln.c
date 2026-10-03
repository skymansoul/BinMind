/* CWE-415: Double-free via wrapper function aliasing.
   free_wrapper(obj) internally frees, caller also frees → double-free */
#include <stdio.h>
#include <stdlib.h>
typedef struct { char *buf; } Container;
void cleanup(Container *c) { free(c->buf); free(c); }
int main(void) {
    Container *c = malloc(sizeof(Container));
    c->buf = malloc(64);
    snprintf(c->buf, 64, "payload");
    cleanup(c);   /* frees c->buf and c */
    free(c->buf);  /* double-free: c->buf already freed in cleanup */
    return 0;
}
