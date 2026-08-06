#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct { char *buf; int len; int freed; } Obj;
static Obj *g_obj = NULL;
Obj *alloc_obj(int n) { Obj *o=malloc(sizeof(Obj)); o->buf=malloc(n); o->len=n; o->freed=0; return o; }
void free_obj(Obj *o) { if(o){free(o->buf); free(o); o=NULL;} }
int use_after_free() {
    Obj *p = alloc_obj(256);
    free_obj(p);
    /* BUG: p was freed but used below — UAF if free_obj didn't NULL the caller's copy */
    if (p) { p->buf[0] = 'X'; return 1; }
    return 0;
}
int main() { return use_after_free(); }
