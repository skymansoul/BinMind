#include <stdlib.h>
/* UAF via callback after free */
struct event { void (*cb)(void*); void *arg; };
void trigger(struct event *e) { if(e->cb) e->cb(e->arg); }
int main() { struct event e; e.arg=malloc(128); e.cb=NULL;
  free(e.arg); trigger(&e); return 0; }