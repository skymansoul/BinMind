#include <stdlib.h>
/* UAF via struct field alias */
struct ctx { char *buf; int sz; };
void free_ctx(struct ctx *c) { free(c->buf); }
int main() { struct ctx c; c.buf=malloc(512); c.sz=512;
  free_ctx(&c); c.buf[0]='x'; return 0; }