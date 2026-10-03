
/* 良性: free(p) 后 q 仍指向存活对象并被解引用 — 别名存活. */
#include <stdlib.h>

struct obj { int v; };
static volatile int *sink;

int main(void) {
    struct obj *p = malloc(sizeof(*p));
    struct obj *q = malloc(sizeof(*q));
    free(p);
    sink = &q->v;             /* q 未释放 */
    return sink != 0;
}
